
use crate::{decrypt, Context};
use log::debug;
use tinyvec::TinyVec;
use simple_error::{simple_error, SimpleError};

pub const ARRAY_VEC_SIZE: usize = 64;
pub type ArrVec<T> = TinyVec<[T; ARRAY_VEC_SIZE]>;

pub enum GuessMethod<'a, 'b> {
    MostCommon(u8),
    Crib(&'a [u8], usize),

    // First argument is the crib
    // second argument is search
    #[allow(dead_code)]
    CribAndSearch(&'a [u8], &'b [u8]),
}

impl<'a, 'b> GuessMethod<'a, 'b> {
    // Checks if the guessing method is valid
    // for a certain key length
    fn is_valid(&self, data: &[u8], key_length: usize) -> Result<(), SimpleError> {
        use GuessMethod::*;
        match &self {
            MostCommon(_) => Ok(()),
            CribAndSearch(crib, _) if key_length > crib.len() => {
                Err(simple_error!("The crib is shorter than the key length"))
            }
            Crib(crib, _) if key_length > crib.len() => {
                Err(simple_error!("The crib is shorter than the key length"))
            }
            Crib(crib, offset) if offset + crib.len() > data.len() => {
                Err(simple_error!("The crib is offset too far into the file"))
            }
            _ => Ok(()),
        }
    }

    fn get_key(&self, data: &[u8], context: &mut Context) -> Result<Vec<ArrVec<u8>>, SimpleError> {
        use GuessMethod::*;

        if let Err(e) = self.is_valid(data, context.key_length) {
            return Err(e);
        }

        match self {
            CribAndSearch(crib, search) => {
                let limit = data.len() - crib.len();

                // TODO: search for multiple keys so all data has to be searched
                let progress_bar = context.request_loading_bar(limit);
                let mut result = Vec::with_capacity(100);

                for offset in 0..limit {
                    let mut key_guess: ArrVec<u8> = data
                        .iter()
                        .skip(offset)
                        .take(context.key_length)
                        .enumerate()
                        .map(|(i, &x)| x ^ crib[i])
                        .collect();

                    key_guess.rotate_right(offset % context.key_length);
                    
                    let data_test = decrypt(data, &key_guess);

                    let mut success = false;
                    let mut si = 0;
                    for x in data_test {
                        if x == search[si] {
                            si += 1;
                        } else {
                            si = 0;
                        }

                        if si == search.len() - 1 {
                            success = true;
                            break;
                        }
                    }

                    if success {
                        result.push(key_guess);
                    }

                    progress_bar.inc(1);
                }

                if result.len() == 0 {
                    Err(simple_error!("No suitable keys found"))
                } else {
                    Ok(result)
                }
            }
            _ => {
                let mut key = ArrVec::<u8>::new();
                for i in 0..context.key_length {
                    key.push(self.get_key_at(data, i, context.key_length));
                }

                let vec = Vec::from([key]);
                Ok(vec)
            }
        }
    }

    fn get_key_at(&self, data: &[u8], key_index: usize, key_length: usize) -> u8 {
        use GuessMethod::*;
        match &self {
            MostCommon(common) => {
                let mut freqs = [0usize; 256];
                data.iter()
                    .skip(key_index)
                    .step_by(key_length)
                    .for_each(|x| freqs[*x as usize] += 1);
                let most_freq = freqs
                    .iter()
                    .enumerate()
                    .reduce(|(ci, cx), (i, x)| if x > cx { (i, x) } else { (ci, cx) })
                    .unwrap()
                    .0 as u8;

                debug!("Most frequent byte found was {:#x}", most_freq);
                most_freq ^ common
            }
            Crib(crib, offset) => data[offset + key_index] ^ crib[key_index],
            CribAndSearch(_, _) => {
                unimplemented!("get_key_at cannot be used for enum variant CribAndSearch")
            }
        }
    }
}

pub fn guess_key(
    data: &[u8],
    method: GuessMethod,
    context: &mut Context
) -> Result<Vec<ArrVec<u8>>, SimpleError> {
    method.get_key(data, context)
}
