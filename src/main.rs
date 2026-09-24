use anyhow::Result;
use clap::Parser;

mod cli;
mod record;
mod recordable;
mod replay;
mod replayer;
mod warpspeed;
mod shared_files;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    // Record and replay need the same host (and so guest) address space layout.
    appbox::respawn::respawn()?;

    match args.command {
        cli::Command::Record(args) => {
            record::record(&args)
        }
        cli::Command::Replay(args) => {
            replay::replay(&args)
        }
    }
}
