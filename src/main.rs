use std::ffi::CString;

use clap::Parser;
use log::debug;

mod cli;
mod record;
mod recordable;
mod replay;
mod util;
mod warpspeed;

fn main() {
    let args = cli::Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    if !args.stage2 {
        debug!("Re-execing with no ASLR");
        unsafe {
            let mut pid: nix::libc::pid_t = 0;

            let mut attr: nix::libc::posix_spawnattr_t = std::mem::zeroed();
            let res = nix::libc::posix_spawnattr_init(&mut attr);
            if res != 0 {
                panic!(
                    "posix_spawnattr_init failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            let res = nix::libc::posix_spawnattr_setflags(
                &mut attr,
                util::_POSIX_SPAWN_DISABLE_ASLR as i16,
            );
            if res != 0 {
                panic!(
                    "posix_spawnattr_setflags failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            let executable = CString::new(std::env::args().next().unwrap()).unwrap();
            let mut all_args = std::env::args().collect::<Vec<_>>();
            all_args.insert(1, "--stage2".to_string());
            let argv = util::CStringArray::new(&all_args);
            let all_env = std::env::vars()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>();
            let env = util::CStringArray::new(&all_env);

            let res = nix::libc::posix_spawn(
                &mut pid,
                executable.as_ptr(),
                std::ptr::null(),
                &attr,
                argv.as_ptr(),
                env.as_ptr(),
            );
            if res != 0 {
                panic!("posix_spawn failed: {}", std::io::Error::last_os_error());
            }

            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).unwrap();
        }

        return;
    }

    match args.command {
        cli::Command::Record(args) => {
            record::record(&args);
        }
        cli::Command::Replay(args) => {
            replay::replay(&args);
        }
    }
}
