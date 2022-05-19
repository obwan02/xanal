use clap::Parser;
use flexi_logger::{Level, Logger};
use log::error;
use xanal::{run, Config};

pub fn format_func(
    w: &mut dyn std::io::Write,
    _now: &mut flexi_logger::DeferredNow,
    record: &flexi_logger::Record,
) -> Result<(), std::io::Error> {
    let level = record.level();

    let marker = match level {
        Level::Error => flexi_logger::style(Level::Error).paint("!"),
        Level::Warn => flexi_logger::style(Level::Warn).paint("?"),
        Level::Info => flexi_logger::style(Level::Debug).paint("*"),
        Level::Debug => flexi_logger::style(Level::Trace).paint("d"),
        Level::Trace => flexi_logger::style(Level::Info).paint("t"),
    };

    write!(w, "[{marker}] {msg}", marker = marker, msg = record.args(),)
}

pub fn format_func_no_color(
    w: &mut dyn std::io::Write,
    _now: &mut flexi_logger::DeferredNow,
    record: &flexi_logger::Record,
) -> Result<(), std::io::Error> {
    write!(w, "{}", record.args().to_string())
}

fn main() {
    let config = Config::parse();

    let format = if config.no_color_output {
        format_func_no_color
    } else {
        format_func
    };

    let mut logger = Logger::try_with_str("info")
        .unwrap()
        .format(format)
        .start()
        .unwrap();

    let result = run(config, || logger.parse_new_spec("debug").unwrap());
    if let Err(e) = result {
        error!("error: {}", e);
    }
}
