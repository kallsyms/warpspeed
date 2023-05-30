use clap::Parser;
use hyperpom::applevisor as av;
use hyperpom::config::*;
use hyperpom::core::*;
use log::{debug, error, info, trace, warn};
//use mach_object::{LoadCommand, MachCommand, MachHeader, OFile, CPU_TYPE_ARM64, CPU_TYPE_X86_64};

mod macho_loader;

/// mRR, the macOS Record Replay Debugger
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

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

fn main() {
    let args = Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let gdata = macho_loader::GlobalData;
    let ldata = macho_loader::LocalData {
        // This is initialized by loader.map. Just needs to be here for access in hooks
        shared_cache_base: 0,
    };

    let loader = macho_loader::MachOLoader::new(&args.executable, &args.arguments)
        .expect("could not create loader");

    let config = ExecConfig::builder(0x10_0000_0000).build();

    let mut executor =
        Executor::<_, _, _>::new(config, loader, ldata, gdata).expect("could not create executor");

    executor.init().expect("could not init executor");
    executor.vcpu.set_reg(av::Reg::LR, 0xdeadf000).unwrap();
    executor.run(None).expect("execution failed");
}
