use clap::Parser;
use log::{debug, error, info, trace, warn};
use mach_object::{LoadCommand, MachCommand, MachHeader, OFile, CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use nix::libc::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use std::fs::File;
use std::io::{Cursor, Read};
use std::os::fd::AsRawFd;

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

fn get_arm64_file(cur: &mut Cursor<&[u8]>) -> Result<(MachHeader, Vec<MachCommand>), String> {
    match OFile::parse(cur).unwrap() {
        OFile::MachFile { header, commands } => {
            return Ok((header, commands));
        }
        // yay copilot generated code
        OFile::FatFile { magic, files } => {
            let mut found = false;
            for (arch, file) in files {
                if arch.cputype == CPU_TYPE_ARM64 {
                    match file {
                        OFile::MachFile { header, commands } => {
                            return Ok((header, commands));
                        }
                        _ => return Err("not a mach file".to_string()),
                    }
                }
            }
        }
        _ => return Err("not a mach file".to_string()),
    }
    Err("not a mach file".to_string())
}

fn convert_prot(prot: i32) -> nix::sys::mman::ProtFlags {
    let mut flags = nix::sys::mman::ProtFlags::empty();
    if prot & VM_PROT_EXECUTE != 0 {
        flags |= nix::sys::mman::ProtFlags::PROT_EXEC;
    }
    if prot & VM_PROT_WRITE != 0 {
        flags |= nix::sys::mman::ProtFlags::PROT_WRITE;
    }
    if prot & VM_PROT_READ != 0 {
        flags |= nix::sys::mman::ProtFlags::PROT_READ;
    }
    flags
}

fn main() {
    let args = Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let mut executable_file = File::open(args.executable).unwrap();
    let mut executable = Vec::new();
    let size = executable_file.read_to_end(&mut executable).unwrap();

    let mut cur = Cursor::new(&executable[..size]);

    let (mach_header, mach_commands) = get_arm64_file(&mut cur).unwrap();
    dbg!(mach_header);

    let mut entry_point: u64 = 0;
    let mut regions = Vec::new();

    // See https://github.com/darlinghq/darling/blob/master/src/startup/mldr/loader.c#L50
    for MachCommand(cmd, _cmdsize) in mach_commands {
        match cmd {
            LoadCommand::Segment64 {
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                ..
            } => {
                let maxprot = convert_prot(maxprot);
                let initprot = convert_prot(initprot);
                let useprot = if initprot.intersects(nix::sys::mman::ProtFlags::PROT_EXEC) {
                    maxprot
                } else {
                    initprot
                };

                if vmaddr == 0 {
                    continue;
                }
                if filesize < vmsize {}

                if filesize > 0 {
                    debug!("mapping {} bytes at 0x{:x}", filesize, vmaddr);
                    unsafe {
                        nix::sys::mman::mmap(
                            std::num::NonZeroUsize::new(vmaddr),
                            std::num::NonZeroUsize::new_unchecked(filesize),
                            useprot,
                            nix::sys::mman::MapFlags::MAP_PRIVATE
                                | nix::sys::mman::MapFlags::MAP_FIXED,
                            executable_file.as_raw_fd(),
                            fileoff as i64, // TODO: plus fat offset
                        )
                        .unwrap();
                    };
                    regions.push((vmaddr, filesize, useprot));
                }
            }
            LoadCommand::UnixThread { state, .. } => {
                if let mach_object::ThreadState::Arm64 { __pc, .. } = state {
                    entry_point = __pc;
                } else {
                    panic!("not arm64");
                }
            }
            LoadCommand::LoadDyLinker(path) => {
                dbg!(path);
            }
            _ => {}
        }
    }

    xhypervisor::create_vm().unwrap();
    for (addr, len, privs) in regions {
        let mut perms = xhypervisor::MemPerm::Read;
        if privs.intersects(nix::sys::mman::ProtFlags::PROT_EXEC) {
            perms = xhypervisor::MemPerm::ExecAndRead;
        } else if privs.intersects(nix::sys::mman::ProtFlags::PROT_WRITE) {
            perms = xhypervisor::MemPerm::Write;
        }
        xhypervisor::map_mem(
            unsafe { std::slice::from_raw_parts_mut(addr as *mut _, len) },
            addr as u64,
            perms,
        )
        .unwrap();
    }

    let vcpu = xhypervisor::VirtualCpu::new().unwrap();
    vcpu.write_register(xhypervisor::Register::CPSR, 0x3c4)
        .unwrap();
    vcpu.write_register(xhypervisor::Register::PC, entry_point)
        .unwrap();

    loop {
        vcpu.run().unwrap();
        match vcpu.exit_reason() {
            xhypervisor::VirtualCpuExitReason::Exception { exception } => {
                let ec = (exception.syndrome >> 26) & 0x3f;
                dbg!(ec);
                break;
            }
            reason => {
                dbg!(reason);
                break;
            }
        }
    }
}
