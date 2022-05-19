use std::error::Error;
use crate::Context;
use log::debug;
use simple_error::{simple_error, SimpleError};
use tinyvec::TinyVec;

pub const ARRAY_VEC_SIZE: usize = 64;
pub type ArrVec<T> = TinyVec<[T; ARRAY_VEC_SIZE]>;

pub enum GuessMethod<'a> {
    MostCommon(u8),
    KeyElimination(&'a [u8]),
}

impl<'a> GuessMethod<'a> {
    // Checks if the guessing method is valid
    // for a certain key length
    fn is_valid(&self, _data: &[u8], key_length: usize) -> Result<(), SimpleError> {
        use GuessMethod::*;
        match &self {
            MostCommon(_) => Ok(()),
            KeyElimination(crib) if key_length >= crib.len() => Err(simple_error!(
                "The crib should be at least one character longer than the key length"
            )),
            _ => Ok(()),
        }
    }

    fn get_key(&self, data: &[u8], context: &mut Context) -> Result<Vec<ArrVec<u8>>, SimpleError> {
        use GuessMethod::*;

        if let Err(e) = self.is_valid(data, context.key_length) {
            return Err(e);
        }

        match self {
            KeyElimination(crib) => {
                // TODO: search for multiple keys so all data has to be searched
                let mut keys = Vec::with_capacity(100);

                let crib_diff: Vec<u8> = crib
                    .iter()
                    .zip(&crib[context.key_length..])
                    .map(|(x, y)| x ^ y)
                    .collect();

                let enc_diff: Vec<u8> = data
                    .iter()
                    .zip(&data[context.key_length..])
                    .map(|(x, y)| x ^ y)
                    .collect();


                let len = enc_diff.len() - crib_diff.len();
                let loading_bar = context.request_loading_bar(enc_diff.len());

                for i in 0..len {
                    let end_index = i + crib_diff.len();
                    if &enc_diff[i..end_index] == &crib_diff {
                        let key: ArrVec<u8> = crib[0..context.key_length]
                            .iter()
                            .zip(&data[i..])
                            .map(|(x, y)| x ^ y)
                            .collect();
                        keys.push(key);
                    }

                    loading_bar.inc(1);
                }

                loading_bar.finish();

                Ok(keys)
            }

            MostCommon(common) => {
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
                    key.push(most_freq ^ common)
                }

                let mut keys = Vec::new();
                keys.push(key);
                Ok(keys)
            }
        }
    }
}

pub fn guess_key(
    data: &[u8],
    method: GuessMethod,
    context: &mut Context,
) -> Result<Vec<ArrVec<u8>>, impl Error> {
    method.get_key(data, context)
}
