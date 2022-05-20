use clap::{Parser, Subcommand};
use log::{info, warn};
use simple_error::{simple_error, SimpleError};
use std::{
    error::Error,
    ffi::OsStr,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{self, stdin, Read, Write},
    path::Path,
};

#[cfg(not(test))]
use std::process;

mod key_guess;
mod kl_anal;

#[derive(Parser, Debug)]
#[clap(author = "Oliver W. (obwan02)", version, about, long_about = None)]
pub struct Config {
    #[clap(subcommand)]
    command: Commands,

    /// The output file to write the decrypted output to
    ///
    /// This flag is optional. If provided, the decrypted output
    /// will be written to the specified file. It will only write to
    /// the file if there are no errors during other stages of the program.
    #[clap(short, long, global = true)]
    output_file: Option<String>,

    /// The maximum key length to check for key length analysis
    ///
    /// During the key length analysis stage, a range of
    /// key lengths are checked, and the key length that
    /// gives the closest ic value to the target ic value is
    /// selected. The max-key-length param is the upper bound
    /// (inclusive) of the key lengths to check.
    #[clap(short, long, default_value_t = 32, global = true)]
    max_key_length: usize,

    /// A specific key length to use to guess the key (skips key length analysis)
    ///
    /// Using this options skips the key length analysis stage,
    /// and instead of guessing the key length, uses the one  
    /// provided.
    #[clap(short = 'k', long = "key-length", global = true)]
    specific_key_length: Option<usize>,

    /// The target index of coincidence to use for key length analysis.
    ///
    /// The key length analysis is done through comparing index of
    /// coincidences for different key lengths. The key length that
    /// gives the closest index of coincidence to the target ic is the
    /// key length that is chosen. This argument specifies the target ic
    /// to compare against (not normalised). By default it is the index of coincidence of
    /// the english langauge.
    #[clap(short, long = "target-ic", default_value_t = 0.067, global = true)]
    target_ic: f32,

    /// Specifies if the output should be verbose or not
    #[clap(short, long, global = true)]
    pub verbose: bool,

    /// Specifies if the output shouldn't be colored
    ///
    /// This option is mainly for use in scripts and other
    /// programs where you just want raw standard ouptut
    #[clap(long, global = true)]
    pub no_color_output: bool,

    /// Specifies that only key length analysis should be run
    ///
    /// This option will make only the key length analysis portion
    /// of the program run.
    #[clap(short = 'l', long, global = true)]
    pub key_length_only: bool,
}

pub struct Context {
    loading_bar: Option<indicatif::ProgressBar>,
    key_length: usize,
}

impl Context {
    fn new(key_length: usize) -> Self {
        Context {
            loading_bar: None,
            key_length,
        }
    }

    fn request_loading_bar(&mut self, len: usize) -> indicatif::ProgressBar {
        self.loading_bar = Some(indicatif::ProgressBar::new(len as u64));
        self.loading_bar
            .as_ref()
            .unwrap()
            .set_style(indicatif::ProgressStyle::default_bar().template(
            "{percent:>3}% [{elapsed_precise}] {bar:40.green/white} {bytes:>7}/{total_bytes:7} [eta {eta_precise}]",
        ).progress_chars("▰▱"));
        self.loading_bar.as_ref().unwrap().clone()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Some(x) = self.loading_bar.as_ref() {
            if !x.is_finished() {
                x.finish_and_clear();
            }
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Perform most common byte analysis on the input data
    ///
    /// This form of analysis is best used for lots of data. It works by
    /// analysing every 'key length'th byte and finding the most common byte.
    /// It then XORs this byte with the provided most common byte (default 32 which is an ascii
    /// space) to find the nth key character.
    #[clap(name = "common")]
    MostCommon {
        /// The file to analyse
        ///
        /// Specifies the input file for xanal to analyse.
        /// A '-' can be provided to read from stdin. If reading
        /// from stdin, the program will output after an EOF.
        #[clap(short = 'f')]
        file: String,

        /// Specifies the most common byte that should be used in analysis
        ///
        /// This argument specifies (in integer form) the most common byte
        /// that should be used when cracking the key. Default is 32, which is
        /// an ascii ' '.
        most_common_byte: Option<u8>,
    },

    /// Perform key elimination using a crib (known plaintext)
    ///
    /// The provided crib should be at least 4 characters longer then the key length
    /// to make an accurate guesses. This method is fairly detailed and to read futher
    /// visit https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Key_elimination
    #[clap(name = "crib")]
    KeyElimination {
        /// The file to analyse
        ///
        /// Specifies the input file for xanal to analyse.
        /// A '-' can be provided to read from stdin. If reading
        /// from stdin, the program will output after an EOF.
        #[clap(short = 'f')]
        file: String,

        /// Specifies the crib to use with key elimination
        ///
        /// This argument specifies the crib to use for key elimination. The longer
        /// the key the more accurate the results will be. They key must be at least as long
        /// as the guessed key length + 1. Note that having a crib only 1 longer than the key
        /// length will probably give you garbage results, and you should aim to have a crib that
        /// is at least 4 characters longer than the estimated key length for accurate results.
        crib: String,
    },
}

#[cfg(test)]
pub fn exit(_: i32, message: impl Display) {
    panic!("{}", message);
}

#[cfg(not(test))]
pub fn exit(code: i32, _: impl Display) {
    process::exit(code);
}

pub fn decrypt<'a>(data: &'a [u8], key: &'a [u8]) -> impl Iterator<Item = u8> + 'a {
    data.iter()
        .enumerate()
        .map(|(i, &x)| x ^ key[i % key.len()])
}

fn read_input(config: &Config) -> Result<Vec<u8>, io::Error> {
    let mut buf = vec![];

    let file = match &config.command {
        Commands::MostCommon { ref file, .. } => file,
        Commands::KeyElimination { ref file, .. } => file,
    };

    if file.as_str() == "-" {
        stdin().lock().read_to_end(&mut buf)?;
        return Ok(buf);
    }

    let mut file = File::open(&file)?;
    file.read_to_end(&mut buf)?;

    Ok(buf)
}

fn write_file(file_path: impl AsRef<Path>, data: &[u8]) -> Result<(), impl Error> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);

    let mut file = options.open(file_path).map_err(SimpleError::from)?;
    file.write_all(data).map_err(SimpleError::from)
}

pub fn run(config: Config, enable_verbose: impl FnOnce() -> ()) -> Result<(), Box<dyn Error>> {
    use key_guess::*;

    if config.verbose {
        enable_verbose();
    }

    let data = read_input(&config)?;
    if data.len() == 0 {
        return Err(Box::new(simple_error!("No data was provided")));
    }

    let key_length = if let Some(x) = config.specific_key_length {
        info!("Using Key Length: {}", x);
        x
    } else {
        let x = kl_anal::analyse_key_length(&data, config.max_key_length, 0.067);

        if x == 0 {
            return Err(Box::new(simple_error!("Guessed key length is 0")));
        }

        info!("Key Length Guess: {}", x);
        x
    };

    if config.key_length_only {
        return Ok(());
    }

    // Establish context
    let mut context = Context::new(key_length);

    let method = match &config.command {
        Commands::MostCommon {
            most_common_byte: x,
            ..
        } => GuessMethod::MostCommon(x.unwrap_or(32)),
        Commands::KeyElimination { crib, .. } => GuessMethod::KeyElimination(crib.as_bytes()),
    };

    // We need to warn users about using the most common method with very few data points.
    // This is because frequency analysis isn't very effective with much data. I choose the warning
    // point as 30 characters because everybody always says 30 is a good sample size (it also is
    // probably a bare minimum in case of frequency analysis because the range of .
    if matches!(method, GuessMethod::MostCommon(..)) && data.len() / key_length < 30 {
        warn!("The selected key length probably does not give enough data to analyse");
    }

    let key_guesses = guess_key(&data, method, &mut context)?;

    // The guess key function is never supposed to return 0 keys
    // (if it does it returns an Err instead). However, it never hurts to
    // be safe.
    if key_guesses.len() == 0 {
        return Err(Box::new(simple_error!("No suitable keys founds")));
    }

    for (i, item) in key_guesses.iter().enumerate() {
        let index_name = format!(" Guess #{} ", i);
        info!("{:-^36}", index_name);
        info!("Key Guess: {}", String::from_utf8_lossy(item));
        info!("Key Guess (base64): {}", base64::encode(item));
        info!("Key Guess (hex): 0x{}", hex::encode(item));
    }

    if let Some(output_file) = config.output_file {
        match key_guesses.len() {
            0 => return Err(Box::new(simple_error!("No keys found"))),
            1 => write_file(
                output_file,
                &decrypt(&data, &key_guesses[0]).collect::<Vec<_>>(),
            )?,
            _ => {
                for (i, key) in key_guesses.iter().enumerate() {
                    let path = std::path::Path::new(&output_file);
                    let dot = if path.extension().is_some() { "." } else { "" };
                    let path = path.with_file_name(&format!(
                        "{}-{}{}{}",
                        path.file_stem()
                            .unwrap_or(OsStr::new(""))
                            .to_str()
                            .unwrap_or(""),
                        i,
                        dot,
                        path.extension()
                            .unwrap_or(OsStr::new(""))
                            .to_str()
                            .unwrap_or(""),
                    ));

                    write_file(path, &decrypt(&data, key).collect::<Vec<_>>())?;
                }
            }
        }
    }

    Ok(())
}
