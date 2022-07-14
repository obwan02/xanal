use crate::Context;
use log::{debug, warn};
use simple_error::simple_error;
use std::error::Error;
use tinyvec::TinyVec;

pub const ARRAY_VEC_SIZE: usize = 64;
pub type ArrVec<T> = TinyVec<[T; ARRAY_VEC_SIZE]>;


pub trait GuessMethod {
    fn is_valid(&self, data: &[u8], context: &Context) -> Result<(), Box<dyn Error>>;
    fn guess_key(&self, data: &[u8], context: &mut Context) -> Vec<ArrVec<u8>>;
}

pub struct MostCommonMethod{ pub common: u8 }
pub struct KeyEliminationMethod<'a>{ pub crib: &'a [u8] }

impl<'a> GuessMethod for MostCommonMethod {
    // Checks if the guessing method is valid
    // for a certain key length
    fn is_valid(&self, data: &[u8], context: &Context) -> Result<(), Box<dyn Error>> {
        
        // We need to warn users about using the most common method with very few data points.
        // This is because frequency analysis isn't very effective with much data. I choose the warning
        // point as 30 characters because everybody always says 30 is a good sample size (it also is
        // probably a bare minimum in case of frequency analysis because the range of .
        if data.len() / context.key_length < 30 {
            warn!("The selected key length probably does not give enough data to analyse");
        }

        Ok(())
    }

    fn guess_key(&self, data: &[u8], context: &mut Context) -> Vec<ArrVec<u8>> {
        let mut key = ArrVec::<u8>::new();
        for i in 0..context.key_length {
            let mut freqs = [0usize; 256];
            data.iter()
                .skip(i)
                .step_by(context.key_length)
                .for_each(|x| freqs[*x as usize] += 1);
            let most_freq = freqs
                .iter()
                .enumerate()
                .reduce(|(ci, cx), (i, x)| if x > cx { (i, x) } else { (ci, cx) })
                .unwrap()
                .0 as u8;

            debug!("Most frequent byte found was {:#x}", most_freq);
            key.push(most_freq ^ self.common)
        }

        let mut keys = Vec::new();
        keys.push(key);
        keys
    }
}

impl<'a> GuessMethod for KeyEliminationMethod<'a> {
    fn is_valid(&self, data: &[u8], context: &Context) -> Result<(), Box<dyn Error>> {
        if context.key_length >= self.crib.len() {
            return Err(simple_error!("The crib should be at least one character longer than the key length"))?;
        }

        if self.crib.len() > data.len() {
            return Err(simple_error!("The crib cannot be longer than the data provided"))?;
        }

        Ok(())
    }

    fn guess_key(&self, data: &[u8], context: &mut Context) -> Vec<ArrVec<u8>> {
        let mut keys = Vec::with_capacity(100);

        let crib_diff: Vec<u8> = self.crib
            .iter()
            .zip(&self.crib[context.key_length..])
            .map(|(x, y)| x ^ y)
            .collect();

        let enc_diff: Vec<u8> = data
            .iter()
            .zip(&data[context.key_length..])
            .map(|(x, y)| x ^ y)
            .collect();

        let len = enc_diff.len() - crib_diff.len();
        debug!("searching through length {}", len);
        let loading_bar = context.request_loading_bar(enc_diff.len());

        for i in 0..len {
            let end_index = i + crib_diff.len();
            if &enc_diff[i..end_index] == &crib_diff {
                let mut key: ArrVec<u8> = self.crib[0..context.key_length]
                    .iter()
                    .zip(&data[i..])
                    .map(|(x, y)| x ^ y)
                    .collect();
                key.rotate_right(i % context.key_length);
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }

            loading_bar.inc(1);
        }

        loading_bar.finish();

        keys
    } 
}

pub fn guess_key(
    data: &[u8],
    method: &dyn GuessMethod,
    context: &mut Context,
) -> Result<Vec<ArrVec<u8>>, Box<dyn Error>> {
    method.is_valid(data, context)?;
    Ok(method.guess_key(data, context))
}
