use clap::Parser;

mod cli;
mod dtrace;
mod mach;
mod record;
mod recordable;
mod replay;
mod util;

fn main() {
    let args = cli::Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    match args.command {
        cli::Command::Record(args) => {
            record::record(&args);
        }
        cli::Command::Replay(args) => {
            replay::replay(&args);
        }
    }
}
