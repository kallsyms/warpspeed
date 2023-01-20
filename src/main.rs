use clap::Parser;
use log::{trace, debug, info, warn, error};
use mach::message::mach_msg_header_t;
use nix::libc;
use nix::sys::signal::{kill, Signal};
use nix::sys::{ptrace};
use nix::unistd::{execve, fork, getpid, ForkResult};
use std::ffi::CStr;
use std::ffi::CString;

// Extra stuff that's not in the mach crate yet.
//mod mach_ext;

extern {
    pub fn task_set_exception_ports(
        task: mach::mach_types::task_t,
        exception_mask: mach::exception_types::exception_mask_t,
        new_port: mach::port::mach_port_t,
        behavior: mach::exception_types::exception_behavior_t,
        new_flavor: mach::thread_status::thread_state_flavor_t,
    ) -> mach::kern_return::kern_return_t;
    pub fn mach_port_request_notification(task: mach::mach_types::ipc_space_t,
                                          name: mach::port::mach_port_name_t,
                                          msgid: mach::message::mach_msg_id_t,
                                          sync: mach::vm_types::natural_t, // mach::port::mach_port_mscount_t,
                                          notify: mach::port::mach_port_t,
                                          notifyPoly: mach::message::mach_msg_type_name_t,
                                          previous: *mut mach::port::mach_port_t,
    ) -> mach::kern_return::kern_return_t;
    pub fn mach_error_string(error_value: mach::kern_return::kern_return_t) -> *const std::os::raw::c_char;

    fn mach_exc_server(
        request: *mut mach_msg_header_t,
        reply: *mut mach_msg_header_t,
    ) -> bool;
}
pub const MACH_NOTIFY_DEAD_NAME: i32 = 0o110;

/// mRR, the macOS Record Replay Debugger
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, trailing_var_arg=true)]
struct Args {
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// Target executable
    #[clap(required = true)]
    executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[test]
fn test_args() {
    let args = Args::parse_from(vec!["mrr", "executable", "--", "-a", "1"]);
    assert_eq!(args.executable, "executable");
    assert_eq!(args.arguments, vec!["-a", "1"]);
}

fn ptrace_attachexc(pid: nix::unistd::Pid) -> nix::Result<()> {
    unsafe {
        nix::errno::Errno::result(libc::ptrace(
            ptrace::Request::PT_ATTACHEXC as ptrace::RequestType,
            pid.into(),
            std::ptr::null_mut(),
            0,
        ))
        .map(|_| ())
    }
}

fn target(executable: &str, args: &Vec<String>) {
    ptrace::traceme().unwrap();
    kill(getpid(), Signal::SIGSTOP).unwrap();

    let executable = CString::new(executable.as_bytes()).unwrap();
    let mut cargs_owned: Vec<CString> = vec![CString::new(executable.as_bytes()).unwrap()];
    cargs_owned.extend(args.iter().map(|s| CString::new(s.as_bytes()).unwrap()));
    let args: Vec<&CStr> = cargs_owned.iter().map(|s| s.as_c_str()).collect();
    let env: Vec<&CStr> = vec![]; // TODO

    debug!("Executing target: {:?} {:?}", executable, args);

    if execve(&executable, &args, &env).is_err() {
        warn!("Failed to execve");
    }
}

fn check_return(r: mach::kern_return::kern_return_t) -> Result<(), &'static str> {
    if r != mach::kern_return::KERN_SUCCESS {
        unsafe {
            Err(CStr::from_ptr(mach_error_string(r)).to_str().unwrap())
        }
    } else {
        Ok(())
    }
}

pub extern fn catch_mach_exception_raise() -> mach::kern_return::kern_return_t {
    error!("Unexpected mach_exception_raise");
    return mach::message::MACH_RCV_INVALID_TYPE;
}

pub extern fn catch_mach_exception_raise_state(
    exception_port: mach::port::mach_port_t,
    exception: mach::exception_types::exception_type_t,
    code: mach::exception_types::exception_data_t,
    code_count: mach::message::mach_msg_type_number_t,
    flavor: *mut mach::thread_status::thread_state_flavor_t,
    old_state: mach::thread_status::thread_state_t,
    old_state_count: mach::message::mach_msg_type_number_t,
    new_state: mach::thread_status::thread_state_t,
    new_state_count: *mut mach::message::mach_msg_type_number_t,
) -> mach::kern_return::kern_return_t {
    info!("Got mach_exception_raise_state: port: {:?}, exception: {:?}, code: {:?}, code_count: {:?}, flavor: {:?}, old_state: {:?}, old_state_count: {:?}, new_state: {:?}, new_state_count: {:?}",
          exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count);
    return mach::kern_return::KERN_SUCCESS;
}

pub extern fn catch_mach_exception_raise_state_identity() -> mach::kern_return::kern_return_t {
    error!("Unexpected mach_exception_raise_state_identity");
    return mach::message::MACH_RCV_INVALID_TYPE;
}

fn main() {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    trace!("{:?}", catch_mach_exception_raise_state as *const ());

    let f;
    unsafe {
        // TODO: use posix_spawn instead
        // https://github.com/headcrab-rs/headcrab/blob/master/src/target/macos.rs#L150
        f = fork().unwrap();
    }

    match f {
        ForkResult::Parent { child, .. } => {
            info!("Child pid {}", child);

            ptrace_attachexc(child).unwrap();

            // https://www.spaceflint.com/?p=150
            // https://sourcegraph.com/github.com/hhhaiai/decompile/-/blob/bin/radareorg_radare2/libr/debug/p/native/xnu/xnu_excthreads.c?L455:23
            let mut task_port: mach::port::mach_port_t = 0;
            let mut exception_port: mach::port::mach_port_name_t = 0;
            unsafe {
                check_return(mach::traps::task_for_pid(mach::traps::mach_task_self(), child.into(), &mut task_port)).unwrap();
                trace!("task_port: {}", task_port);

                check_return(mach::mach_port::mach_port_allocate(
                    mach::traps::mach_task_self(),
                    mach::port::MACH_PORT_RIGHT_RECEIVE,
                    &mut exception_port,
                )).unwrap();
                trace!("exception_port: {}", exception_port);

                check_return(mach::mach_port::mach_port_insert_right(
                    mach::traps::mach_task_self(),
                    exception_port,
                    exception_port,
                    mach::message::MACH_MSG_TYPE_MAKE_SEND,
                )).unwrap();
                check_return(task_set_exception_ports(
                    task_port,
                    mach::exception_types::EXC_MASK_ALL,
                    exception_port,
                    // TODO: request state
                    mach::exception_types::EXCEPTION_STATE as i32,
                    // (mach::exception_types::EXCEPTION_DEFAULT
                    //     | mach::exception_types::MACH_EXCEPTION_CODES) as i32,
                    //mach::thread_status::THREAD_STATE_NONE,
                    mach::thread_status::x86_THREAD_STATE64,
                )).unwrap();

                let mut req_port: mach::port::mach_port_t = 0;
                check_return(mach_port_request_notification(
                    mach::traps::mach_task_self(),
                    task_port,
                    MACH_NOTIFY_DEAD_NAME,
                    0,
                    exception_port,
                    mach::message::MACH_MSG_TYPE_MAKE_SEND_ONCE,
                    &mut req_port,
                )).unwrap();
            }

            loop {
                let mut req: [u8; 4096] = [0; 4096];
                let req_hdr = &mut req as *mut _ as *mut mach_msg_header_t;
                let mut rpl: [u8; 4096] = [0; 4096];
                let rpl_hdr = &mut rpl as *mut _ as *mut mach_msg_header_t;

                unsafe {
                    check_return(mach::message::mach_msg(
                        req_hdr,
                        mach::message::MACH_RCV_MSG,
                        0,
                        4096,
                        exception_port,
                        mach::message::MACH_MSG_TIMEOUT_NONE,
                        mach::port::MACH_PORT_NULL,
                    )).unwrap();

                    // Will call back into catch_mach_exception_raise_state
                    if !mach_exc_server(
                        req_hdr,
                        rpl_hdr,
                    ) {
                        warn!("mach_exc_server failed");
                    }

                    check_return(mach::message::mach_msg(
                        rpl_hdr,
                        mach::message::MACH_SEND_MSG,
                        (*rpl_hdr).msgh_size,
                        0,
                        mach::port::MACH_PORT_NULL,
                        mach::message::MACH_MSG_TIMEOUT_NONE,
                        mach::port::MACH_PORT_NULL,
                    )).unwrap();
                }
            }
        }
        ForkResult::Child => {
            target(&args.executable, &args.arguments);
            return;
        }
    }
}
