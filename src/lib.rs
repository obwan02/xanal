use clap::{ArgGroup, Parser};
use log::{error, info, warn};
use simple_error::{simple_error, SimpleError};
use std::{
    error::Error,
    ffi::OsStr,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{stdin, Read, Write, self},
    path::Path,
};

#[cfg(not(test))]
use std::process;

mod key_guess;
mod kl_anal;

#[derive(Parser, Debug)]
#[clap(author = "Oliver W. (obwan02)", version, about, long_about = None)]
#[clap(group(
        ArgGroup::new("method")
        .required(true)
        .args(&["most-common-byte", "crib"])
))]
pub struct Config {
    /// The file to analyse
    ///
    /// Specifies the input file for xanal to analyse.
    /// A '-' can be provided to read from stdin. If reading
    /// from stdin, the program will output after an EOF.
    #[clap(required = true)]
    file: String,

    /// The output file to write the decrypted output to
    ///
    /// This flag is optional. If provided, the decrypted output
    /// will be written to the specified file. It will only write to
    /// the file if there are no errors during other stages of the program.
    #[clap(short, long)]
    output_file: Option<String>,

    /// The maximum key length to check for key length analysis
    ///
    /// During the key length analysis stage, a range of
    /// key lengths are checked, and the key length that
    /// gives the closest ic value to the target ic value is
    /// selected. The max-key-length param is the upper bound
    /// (inclusive) of the key lengths to check.
    #[clap(long, default_value_t = 32)]
    max_key_length: usize,

    /// A specific key length to use to guess the key (skips key length analysis)
    ///
    /// Using this options skips the key length analysis stage,
    /// and instead of guessing the key length, uses the one  
    /// provided.
    #[clap(short = 'k', long = "key-length")]
    specific_key_length: Option<usize>,

    /// The target index of coincidence to use for key length analysis.
    ///
    /// The key length analysis is done through comparing index of
    /// coincidences for different key lengths. The key length that
    /// gives the closest index of coincidence to the target ic is the
    /// key length that is chosen. This argument specifies the target ic
    /// to compare against (not normalised). By default it is the index of coincidence of
    /// the english langauge.
    #[clap(short, long = "target-ic", default_value_t = 0.067)]
    target_ic: f32,

    /// The most common byte for key analysis.
    ///
    /// This is the default analysis option that is used when no arguments are
    /// passed to xanal. The default most common byte is 0x20, which is the space
    /// character. This flag cannot be used in conjunction with the 'crib' flag, which
    /// uses crib analysis for guessing the key.
    #[clap(short = 'c', long, default_value_t = 0x20)]
    most_common_byte: u8,

    /// The crib to be used for key analysis.
    ///
    /// The crib flag specifies that a crib will be used to
    /// find the key. This is an alternative to analysis by
    /// most common byte. Cannot be used in conjunction with the
    /// 'most_common_byte' flag. This flag requires one of
    /// the 'crib-offset' or 'crib-search' flags to be set.
    #[clap(long = "crib", requires = "crib-method")]
    crib: Option<String>,

    /// The crib offset to be used for key analysis
    ///
    /// The crib flag specifies that a key analysis should be done using
    /// a crib. Specifying this flag (crib-offset) uses the mode of crib offset
    /// to recover the key. Cannot be used in conjunction with 'crib-search' flag.
    #[clap(long = "crib-offset", requires = "crib", group = "crib-method")]
    crib_offset: Option<usize>,

    /// The crib search to be used for key analysis
    ///
    /// The crib flag specifies that a key analysis should be done using
    /// a crib. Specifying this flag (crib-search) uses the mode of crib search
    /// to recover the key. This method works by testing the crib in all possible
    /// positions and seeing if the search term appears in the ouptut.
    #[clap(long = "crib-search", requires = "crib", group = "crib-method")]
    crib_search: Option<String>,

    /// Specifies if the output should be verbose or not
    #[clap(short, long)]
    pub verbose: bool,

    /// Specifies if the output shouldn't be colored
    ///
    /// This option is mainly for use in scripts and other
    /// programs where you just want raw standard ouptut
    #[clap(long)]
    pub no_color_output: bool,

    /// Specifies that only key length analysis should be run
    ///
    /// This option will make only the key length analysis portion
    /// of the program run.
    #[clap(short = 'l', long)]
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
        self.loading_bar.as_ref().unwrap().clone()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Some(x) = self.loading_bar.as_ref() {
            x.finish_using_style();
        }
    }
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

    if config.file == "-" {
        stdin().lock().read_to_end(&mut buf)?;
        return Ok(buf);
    }

    let mut file = File::open(&config.file)?;
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

    let key_length = if let Some(x) = config.specific_key_length {
        info!("Using Key Length: {}", x);
        x
    } else {
        let x = kl_anal::analyse_key_length(&data, config.max_key_length, 0.067);
        info!("Key Length Guess: {}", x);
        x
    };

    if config.key_length_only {
        return Ok(());
    }

    // Establish context
    let mut context = Context::new(key_length);

    let method = match (&config.crib, &config.crib_offset, &config.crib_search) {
        (Some(crib), Some(offset), None) => GuessMethod::Crib(crib.as_bytes(), *offset),
        (Some(crib), None, Some(search)) => {
            GuessMethod::CribAndSearch(crib.as_bytes(), search.as_bytes())
        }
        (Some(_), Some(_), Some(_)) => unreachable!(),
        (Some(_), ..) => unreachable!(),
        (None, None, None) => GuessMethod::MostCommon(config.most_common_byte),
        (None, ..) => unreachable!(),
    };

    // We need to warn users about using the most common method with very few data points.
    // This is because frequency analysis isn't very effective with much data. I choose the warning
    // point as 30 characters because everybody always says 30 is a good sample size (it also is
    // probably a bare minimum in case of frequency analysis because the range of .
    if matches!(method, GuessMethod::MostCommon(..)) && data.len() / key_length < 30 {
        warn!("The selected key length probably does not give enough data to analyse");
    }

    // print a empty line before displaying keys
    info!("");

    let key_guesses = guess_key(&data, method, &mut context)?;

    // Drop the context so the loading bar appears correctly
    std::mem::drop(context);

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
                    let path = path.with_file_name(&format!(
                        "{}-{}.{}",
                        path.file_stem()
                            .unwrap_or(OsStr::new(""))
                            .to_str()
                            .unwrap_or(""),
                        i,
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
