use log::debug;
use std::num::NonZeroUsize;

// calc_ic calculates the index of coincidence for
// the provided data over a certain ofsset and step size.
// The IC calculated is not normalised.
fn calc_ic(data: &[u8], offset: usize, step: usize) -> f32 {
    let gen_iter = || data.iter().skip(offset).step_by(step);
    let length = data.iter().skip(offset).step_by(step).count();
    let mut freqs = [0usize; 256];
    gen_iter().for_each(|&byte| freqs[byte as usize] += 1);
    let ic = freqs
        .iter()
        .filter(|x| **x != 0)
        .map(|&x| x * (x - 1))
        .fold(0, |accum, x| accum + x);
    let ic = ic as f32 / (length * (length - 1)) as f32;
    ic
}

fn calc_ic_for_key_length(data: &[u8], key_length: NonZeroUsize) -> f32 {
    let mut mean = 0.0f32;
    for offset in 0..key_length.get() {
        mean += calc_ic(data, offset, key_length.get());
    }

    mean / (key_length.get() as f32)
}

pub fn analyse_key_length(data: &[u8], max_length: usize, target_ic: f32) -> usize {
    let mut ic_vals = Vec::new();
    ic_vals.resize(max_length + 2, f32::MAX);

    let max_length = max_length.min(data.len());

    for i in 1..=max_length {
        let length = NonZeroUsize::new(i).unwrap();
        let ic = calc_ic_for_key_length(data, length);
        ic_vals[i] = ic;
        debug!("Key Length: {}, IC: {}", i, ic);
    }

    ic_vals
        .iter()
        .map(|x| f32::abs(x - target_ic))
        .enumerate()
        .reduce(|(ci, cx), (i, x)| if x < cx { (i, x) } else { (ci, cx) })
        .unwrap()
        .0
}
