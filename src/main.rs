use clap::Parser;
use log::{trace, debug, info, warn, error};
use nix::libc;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::unistd::{execve, fork, getpid, ForkResult, sleep};
use std::ffi::CStr;
use std::ffi::CString;

// Couple of defs which aren't in the mach crate
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
}

#[link(name = "mach_excServer", kind = "static")]
extern {
    fn mach_exc_server(
        request: *mut mach::message::mach_msg_header_t,
        reply: *mut mach::message::mach_msg_header_t,
    ) -> bool;
}

mod mig;

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

fn ptrace_thupdate(pid: nix::unistd::Pid, port: mach::port::mach_port_t, signal: i32) -> nix::Result<()> {
    unsafe {
        nix::errno::Errno::result(libc::ptrace(
            ptrace::Request::PT_THUPDATE as ptrace::RequestType,
            pid.into(),
            port as *mut i8,
            signal,
        ))
        .map(|_| ())
    }
}

fn target(executable: &str, args: &Vec<String>) {
    let executable = CString::new(executable.as_bytes()).unwrap();
    let mut cargs_owned: Vec<CString> = vec![CString::new(executable.as_bytes()).unwrap()];
    cargs_owned.extend(args.iter().map(|s| CString::new(s.as_bytes()).unwrap()));
    let args: Vec<&CStr> = cargs_owned.iter().map(|s| s.as_c_str()).collect();
    let env: Vec<&CStr> = vec![]; // TODO

    debug!("Executing target: {:?} {:?}", executable, args);

    loop {
        println!("hello!");
        sleep(3);
    }

    // if execve(&executable, &args, &env).is_err() {
    //     warn!("Failed to execve");
    // }
}

fn r_mach_error_string(r: mach::kern_return::kern_return_t) -> &'static str {
    unsafe {
        CStr::from_ptr(mach_error_string(r)).to_str().unwrap()
    }
}

fn check_return(r: mach::kern_return::kern_return_t) -> Result<(), &'static str> {
    if r != mach::kern_return::KERN_SUCCESS {
        Err(r_mach_error_string(r))
    } else {
        Ok(())
    }
}

static mut global_child: nix::unistd::Pid = nix::unistd::Pid::from_raw(0);

#[no_mangle]
pub extern fn catch_mach_exception_raise(
    exception_port: mach::port::mach_port_t,
    thread_port: mach::port::mach_port_t,
    task_port: mach::port::mach_port_t,
    exception: mach::exception_types::exception_type_t,
    code: *mut u32, //mach::exception_types::exception_data_t,
    code_count: mach::message::mach_msg_type_number_t,
) -> mach::kern_return::kern_return_t {
    let codes = unsafe { std::slice::from_raw_parts(code, code_count as usize) };
    trace!("mach_exception_raise: {:?} {:?} {:?} {:?} {:?} {:?} ({:?})", exception_port, thread_port, task_port, exception, code, code_count, codes);

    match exception as u32 {
        mach::exception_types::EXC_SOFTWARE => {
            match codes {
                [mach::exception_types::EXC_SOFT_SIGNAL, signal] => {
                    trace!("EXC_SOFT_SIGNAL: {}", signal);
                }
                _ => {
                    info!("Unhandled EXC_SOFTWARE code: {:?}", codes);
                }
            }
            unsafe {
                ptrace_thupdate(global_child, thread_port, codes[1] as i32).unwrap();
            }
        }
        mach::exception_types::EXC_SYSCALL => {
            trace!("EXC_SYSCALL");
        }
        _ => {
            info!("Unhandled exception type: {}", exception);
        }
    };
    return mach::kern_return::KERN_SUCCESS;
}

#[no_mangle]
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
    error!("Unexpected mach_exception_raise_state");
    return mach::message::MACH_RCV_INVALID_TYPE;
}

#[no_mangle]
pub extern fn catch_mach_exception_raise_state_identity() -> mach::kern_return::kern_return_t {
    error!("Unexpected mach_exception_raise_state_identity");
    return mach::message::MACH_RCV_INVALID_TYPE;
}

fn main() {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let f;
    unsafe {
        // TODO: use posix_spawn instead
        // https://github.com/headcrab-rs/headcrab/blob/master/src/target/macos.rs#L150
        f = fork().unwrap();
    }

    match f {
        ForkResult::Parent { child, .. } => {
            unsafe { global_child = child; }
            info!("Child pid {}", child);

            // trace!("Waiting for child STOP");
            // trace!("{:?}", waitpid(child, None).unwrap());

            // https://www.spaceflint.com/?p=150
            // https://sourcegraph.com/github.com/hhhaiai/decompile/-/blob/bin/radareorg_radare2/libr/debug/p/native/xnu/xnu_excthreads.c?L455:23
            let mut task_port: mach::mach_types::task_t = 0;
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
                    (mach::exception_types::EXCEPTION_DEFAULT
                        | mach::exception_types::MACH_EXCEPTION_CODES) as i32,
                    //mach::thread_status::THREAD_STATE_NONE,  // causes invalid arg?
                    mach::thread_status::x86_THREAD_STATE64,
                )).unwrap();
                trace!("set exception port");

                let mut req_port: mach::port::mach_port_t = 0;
                check_return(mach_port_request_notification(
                    mach::traps::mach_task_self(),
                    task_port,
                    mig::MACH_NOTIFY_DEAD_NAME as i32,  // steal the def from mig here
                    0,
                    exception_port,
                    mach::message::MACH_MSG_TYPE_MAKE_SEND_ONCE,
                    &mut req_port,
                )).unwrap();
            }

            ptrace_attachexc(child).unwrap();
            trace!("Attached");

            loop {
                let mut req: [u8; 4096] = [0; 4096];
                let req_hdr = &mut req as *mut _ as *mut mach::message::mach_msg_header_t;
                let mut rpl: [u8; 4096] = [0; 4096];
                let rpl_hdr = &mut rpl as *mut _ as *mut mach::message::mach_msg_header_t;

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
                    trace!("Got message: {:?}", *req_hdr);

                    // Will call back into catch_mach_exception_raise
                    if !mach_exc_server(
                        req_hdr,
                        rpl_hdr,
                    ) {
                        if(*req_hdr).msgh_id == mig::MACH_NOTIFY_DEAD_NAME as i32 {
                            info!("Child died");
                            return;
                        }

                        warn!("mach_exc_server failed: {}", r_mach_error_string((*(&mut rpl as *mut _ as *mut mig::mig_reply_error_t)).RetCode));
                    }

                    *rpl_hdr = *req_hdr;
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
