use clap::Parser;
use flexi_logger::Logger;
use xanal::{run, Config};

pub fn format_func(
    w: &mut dyn std::io::Write,
    _now: &mut flexi_logger::DeferredNow,
    record: &flexi_logger::Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "{}",
        flexi_logger::style(level).paint(record.args().to_string())
    )
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

    let logger = Logger::try_with_str("info")
        .unwrap()
        .format(format)
        .start()
        .unwrap();

    run(config, logger);
}
