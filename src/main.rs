use std::ffi::CString;

use anyhow::Result;
use clap::Parser;
use log::{debug, warn};

mod cli;
mod record;
mod recordable;
mod replay;
mod util;
mod warpspeed;
mod shared_files;

const STAGE2_RETRY_EXIT_CODE: i32 = 200;
const MAX_STAGE2_RETRIES: usize = 256;

fn should_retry_stage2(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            == Some(nix::libc::ENOMEM)
    })
}

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    if !args.stage2 {
        debug!("Re-execing with no ASLR");
        unsafe {
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

            let executable = CString::new(
                std::env::args()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing argv[0]"))?,
            )?;
            let mut all_args = std::env::args().collect::<Vec<_>>();
            all_args.insert(1, "--stage2".to_string());
            let argv = util::CStringArray::new(&all_args)?;
            let all_env = std::env::vars()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>();
            let env = util::CStringArray::new(&all_env)?;

            for attempt in 1..=MAX_STAGE2_RETRIES {
                let mut pid: nix::libc::pid_t = 0;
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

                match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None)? {
                    nix::sys::wait::WaitStatus::Exited(_, 0) => return Ok(()),
                    nix::sys::wait::WaitStatus::Exited(_, STAGE2_RETRY_EXIT_CODE) => {
                        if attempt == MAX_STAGE2_RETRIES {
                            return Err(anyhow::anyhow!(
                                "stage2 failed {} times with retryable fixed mapping pool reservation errors",
                                MAX_STAGE2_RETRIES
                            ));
                        }
                        warn!(
                            "Retrying stage2 after fixed mapping pool reservation failure (attempt {}/{})",
                            attempt,
                            MAX_STAGE2_RETRIES
                        );
                    }
                    nix::sys::wait::WaitStatus::Exited(_, code) => std::process::exit(code),
                    status => {
                        return Err(anyhow::anyhow!("unexpected child wait status: {:?}", status));
                    }
                }
            }
        }
    }

    let result = match args.command {
        cli::Command::Record(args) => {
            record::record(&args)
        }
        cli::Command::Replay(args) => {
            replay::replay(&args)
        }
    };

    if let Err(err) = result {
        if should_retry_stage2(&err) {
            std::process::exit(STAGE2_RETRY_EXIT_CODE);
        }
        return Err(err);
    }

    Ok(())
}
