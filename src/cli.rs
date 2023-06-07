use clap::{Args, Parser, Subcommand};

/// mRR, the macOS Record Replay Debugger
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(hide = true, long)]
    pub stage2: bool,

    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Record a trace
    Record(RecordArgs),

    /// Replay a trace
    Replay(ReplayArgs),
}

#[derive(Args)]
#[command(trailing_var_arg = true)]
pub struct RecordArgs {
    /// Output filename of the trace
    #[clap(required = true)]
    pub trace_filename: String,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// Input filename of the trace
    #[clap(required = true)]
    pub trace_filename: String,
}

#[test]
fn test_args() {
    let args = Cli::parse_from(vec![
        "mrr",
        "record",
        "out.log",
        "executable",
        "--",
        "-a",
        "1",
    ]);
    match args.command {
        Command::Record(args) => {
            assert_eq!(args.trace_filename, "out.log");
            assert_eq!(args.executable, "executable");
            assert_eq!(args.arguments, vec!["-a", "1"]);
        }
        _ => panic!("unexpected command"),
    }
}
