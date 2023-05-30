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

    let _vm = av::VirtualMachine::new();
    // Unused, but necessary global and local data structures.
    let gdata = macho_loader::GlobalData;
    let ldata = macho_loader::LocalData {
        // This is initialized by loader.map. Just needs to be here for access in hooks
        shared_cache_base: 0,
    };
    // Instanciates the test loader with our assembled instructions.
    let loader = macho_loader::MachOLoader::new(&args.executable, &args.arguments)
        .expect("could not create loader");
    // Builds a default configuration for the executor with an address space size of, at most,
    // 0x10000000 bytes.
    let config = ExecConfig::builder(0x10000000).build();
    // Instanciates the executor with the values above.
    let mut executor =
        Executor::<_, _, _>::new(config, loader, ldata, gdata).expect("could not create executor");
    executor.init().expect("could not init executor");
    // Runs the executor. It will stop automatically when the `ret` instruction is executed.
    executor.run(None).expect("execution failed");
    // Makes sure that we obtained the expected result of 0x42.
    println!("X0 = {:#x}", executor.vcpu.get_reg(av::Reg::X0).unwrap());
}
