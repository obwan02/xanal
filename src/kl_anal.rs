use console::style;
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
    let max_length = usize::min(max_length, data.len());
    ic_vals.resize(max_length, f32::MAX);

    for i in 1..=max_length {
        let length = NonZeroUsize::new(i).unwrap();
        let ic = calc_ic_for_key_length(data, length);
        ic_vals[i - 1] = ic;
    }

    let mut best_guess_i = 0;
    for i in 0..ic_vals.len() {
        let diff = (ic_vals[i] - target_ic).abs();
        let best_diff = (ic_vals[best_guess_i] - target_ic).abs();

        let mut is_multiple = false;

        // If the ic values are approx the same
        // we check if current key length is a multiple
        // of the previous best. If it is we ignore it
        // otherwise we choose the longer key length
        if diff < best_diff {
            // This is the check for a value being close
            // and checking for multiples
            if (diff - best_diff).abs() <= 0.001 {
                // If the length is not a multiple don't ignore it
                if !((i + 1) % (best_guess_i + 1) == 0) {
                    best_guess_i = i;
                } else {
                    is_multiple = true;
                }
            } else {
                best_guess_i = i
            }
        }

        if is_multiple {
            debug!(
                "Key Length: {}, IC: {} {}",
                i + 1,
                ic_vals[i],
                style(format!("IGNORED: Multiple of {}", best_guess_i + 1)).red()
            );
        } else {
            debug!("Key Length: {}, IC: {}", i + 1, ic_vals[i]);
        }
    }

    best_guess_i + 1
}
