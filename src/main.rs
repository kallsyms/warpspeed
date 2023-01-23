use clap::Parser;
use log::{debug, error, info, trace, warn};
use nix::libc;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{execve, fork, getpid, sleep, ForkResult};
use std::ffi::CStr;
use std::ffi::CString;

// Couple of defs which aren't in the mach crate
extern "C" {
    pub fn task_set_exception_ports(
        task: mach::mach_types::task_t,
        exception_mask: mach::exception_types::exception_mask_t,
        new_port: mach::port::mach_port_t,
        behavior: mach::exception_types::exception_behavior_t,
        new_flavor: mach::thread_status::thread_state_flavor_t,
    ) -> mach::kern_return::kern_return_t;
    pub fn mach_port_request_notification(
        task: mach::mach_types::ipc_space_t,
        name: mach::port::mach_port_name_t,
        msgid: mach::message::mach_msg_id_t,
        sync: mach::vm_types::natural_t, // mach::port::mach_port_mscount_t,
        notify: mach::port::mach_port_t,
        notifyPoly: mach::message::mach_msg_type_name_t,
        previous: *mut mach::port::mach_port_t,
    ) -> mach::kern_return::kern_return_t;
    pub fn mach_error_string(
        error_value: mach::kern_return::kern_return_t,
    ) -> *const std::os::raw::c_char;
}

#[link(name = "mach_excServer", kind = "static")]
extern "C" {
    fn mach_exc_server(
        request: *mut mach::message::mach_msg_header_t,
        reply: *mut mach::message::mach_msg_header_t,
    ) -> bool;
}

mod dtrace;
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

fn ptrace_thupdate(
    pid: nix::unistd::Pid,
    port: mach::port::mach_port_t,
    signal: i32,
) -> nix::Result<()> {
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

// https://stackoverflow.com/a/32270215
extern "C" fn dtrace_agg_walk_handler(agg: *const dtrace::dtrace_aggdata_t, arg: *mut libc::c_void) -> libc::c_int {
    let closure: &mut &mut dyn FnMut(*const dtrace::dtrace_aggdata_t) -> bool = unsafe { std::mem::transmute(arg) };
    closure(agg) as libc::c_int
}

pub fn dtrace_aggregate_walk_cb<F>(handle: *mut dtrace::dtrace_hdl, mut callback: F) -> libc::c_int
    where F: FnMut(*const dtrace::dtrace_aggdata_t) -> libc::c_int
{
    let mut cb: &mut dyn FnMut(*const dtrace::dtrace_aggdata_t) -> libc::c_int = &mut callback;
    let cb = &mut cb;
    unsafe {
        dtrace::dtrace_aggregate_walk(handle, Some(dtrace_agg_walk_handler), cb as *mut _ as *mut libc::c_void)
    }
}

fn target(executable: &str, args: &Vec<String>) -> ! {
    sleep(1);

    let executable = CString::new(executable.as_bytes()).unwrap();
    let mut cargs_owned: Vec<CString> = vec![CString::new(executable.as_bytes()).unwrap()];
    cargs_owned.extend(args.iter().map(|s| CString::new(s.as_bytes()).unwrap()));
    let args: Vec<&CStr> = cargs_owned.iter().map(|s| s.as_c_str()).collect();
    let env: Vec<&CStr> = vec![]; // TODO

    debug!("Executing target: {:?} {:?}", executable, args);

    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    panic!("bye");

    // if execve(&executable, &args, &env).is_err() {
    //     warn!("Failed to execve");
    // }

    // panic!("Return from execve");
}

fn r_mach_error_string(r: mach::kern_return::kern_return_t) -> &'static str {
    unsafe { CStr::from_ptr(mach_error_string(r)).to_str().unwrap() }
}

fn mach_check_return(r: mach::kern_return::kern_return_t) -> Result<(), &'static str> {
    if r != mach::kern_return::KERN_SUCCESS {
        Err(r_mach_error_string(r))
    } else {
        Ok(())
    }
}

static mut global_child: nix::unistd::Pid = nix::unistd::Pid::from_raw(0);
static mut dtrace_handle: *mut dtrace::dtrace_hdl = std::ptr::null_mut();

fn record_syscall(
    number: i32,
    task_port: mach::port::mach_port_t,
    thread_port: mach::port::mach_port_t,
) {
    let regs = unsafe {
        let mut threads: mach::mach_types::thread_act_array_t = std::ptr::null_mut();
        let mut nthreads = 0;
        mach_check_return(mach::task::task_threads(task_port, &mut threads, &mut nthreads)).unwrap();

        trace!("threads {:x?}, count {}", *threads, nthreads);

        let mut count = 64;
        let mut regs: [u64; 64] = [0; 64];
        let r = mach::thread_act::thread_get_state(
            *threads, // thread_port,
            6,
            &mut regs as *mut _ as mach::thread_status::thread_state_t,
            &mut count,
        );
        if r != mach::kern_return::KERN_SUCCESS {
            warn!("thread_get_state failed: {}", r_mach_error_string(r));
            return;
        }
        regs
    };

    trace!("regs {:x?}", regs);

    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/kern/syscalls.master#L45
    match number {
        3 => {
            // read. store the data that was read
            let mut data: Vec<u8> = vec![0; regs[2] as usize];
            let mut copy_size: mach::vm_types::mach_vm_size_t = 0;
            
            let r = unsafe {
                mach::vm::mach_vm_read_overwrite(
                    thread_port,
                    regs[1],
                    regs[2],
                    &mut data as *mut _ as mach::vm_types::mach_vm_address_t,
                    &mut copy_size,
                )
            };
            if r != mach::kern_return::KERN_SUCCESS {
                warn!("vm_read_overwrite failed: {}", r_mach_error_string(r));
            }

            trace!("read({}, _, {}) = {:x?}", regs[0], regs[2], data);
        }
        _ => {
            warn!("Unhandled syscall {}", number);
        }
    }
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise(
    exception_port: mach::port::mach_port_t,
    thread_port: mach::port::mach_port_t,
    task_port: mach::port::mach_port_t,
    exception: mach::exception_types::exception_type_t,
    code: *mut u32, //mach::exception_types::exception_data_t,
    code_count: mach::message::mach_msg_type_number_t,
) -> mach::kern_return::kern_return_t {
    let codes = unsafe { std::slice::from_raw_parts(code, (code_count + 1) as usize) };
    trace!(
        "mach_exception_raise: {:?} {:?} {:?} {:?} {:?} {:?} ({:?})",
        exception_port,
        thread_port,
        task_port,
        exception,
        code,
        code_count,
        codes
    );

    match exception as u32 {
        mach::exception_types::EXC_SOFTWARE => {
            match codes {
                [mach::exception_types::EXC_SOFT_SIGNAL, _, signum] => {
                    let signal: Signal;
                    unsafe {
                        signal = std::mem::transmute(*signum);
                    }
                    trace!("EXC_SOFT_SIGNAL: {}", signal);

                    let mut syscall_number: i32 = 0;

                    unsafe {
                        if dtrace::dtrace_aggregate_snap(dtrace_handle) == -1 {
                            warn!("dtrace_aggregate_snap failed: {}", CStr::from_ptr(dtrace::dtrace_errmsg(dtrace_handle, dtrace::dtrace_errno(dtrace_handle))).to_str().unwrap());
                        }
                        let closure = |agg: *const dtrace::dtrace_aggdata_t| {
                            let desc = *((*agg).dtada_desc);
                            let records: &[dtrace::dtrace_recdesc] = std::slice::from_raw_parts(&(*(*agg).dtada_desc).dtagd_rec as *const dtrace::dtrace_recdesc_t, (desc.dtagd_nrecs) as usize);
                            let mut vals: Vec<i32> = vec![];
                            for rec in records {
                                vals.push(*(((*agg).dtada_data).offset(rec.dtrd_offset as isize) as *const i32));
                            }
                            trace!("dtrace agg vals: {:?}", vals);
                            if vals[2] != 0 {
                                syscall_number = vals[1];
                            }
                            //dtrace::DTRACE_AGGWALK_REMOVE as i32
                            dtrace::DTRACE_AGGWALK_NEXT as i32
                        };
                        dtrace_aggregate_walk_cb(dtrace_handle, closure);
                        dtrace::dtrace_aggregate_clear(dtrace_handle);
                    }

                    trace!("syscall number {}", syscall_number);
                    record_syscall(syscall_number, task_port, thread_port);
                }
                _ => {
                    info!("Unhandled EXC_SOFTWARE code: {:?}", codes);
                }
            }
            // unsafe {
            //     ptrace_thupdate(global_child, thread_port, codes[1] as i32).unwrap();
            // }
        }
        _ => {
            info!("Unhandled exception type: {}", exception);
        }
    };
    // Does returning here implicitly continue?
    return mach::kern_return::KERN_SUCCESS;
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise_state(
    _exception_port: mach::port::mach_port_t,
    _exception: mach::exception_types::exception_type_t,
    _code: mach::exception_types::exception_data_t,
    _code_count: mach::message::mach_msg_type_number_t,
    _flavor: *mut mach::thread_status::thread_state_flavor_t,
    _old_state: mach::thread_status::thread_state_t,
    _old_state_count: mach::message::mach_msg_type_number_t,
    _new_state: mach::thread_status::thread_state_t,
    _new_state_count: *mut mach::message::mach_msg_type_number_t,
) -> mach::kern_return::kern_return_t {
    error!("Unexpected mach_exception_raise_state");
    return mach::message::MACH_RCV_INVALID_TYPE;
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise_state_identity(
    _exception_port: mach::port::mach_port_t,
    _thread_port: mach::port::mach_port_t,
    _task_port: mach::port::mach_port_t,
    _exception: mach::exception_types::exception_type_t,
    _code: mach::exception_types::exception_data_t,
    _code_count: mach::message::mach_msg_type_number_t,
    _flavor: *mut mach::thread_status::thread_state_flavor_t,
    _old_state: mach::thread_status::thread_state_t,
    _old_state_count: mach::message::mach_msg_type_number_t,
    _new_state: mach::thread_status::thread_state_t,
    _new_state_count: *mut mach::message::mach_msg_type_number_t,
) -> mach::kern_return::kern_return_t {
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
            unsafe {
                global_child = child;
            }
            info!("Child pid {}", child);

            // trace!("Waiting for child STOP");
            // trace!("{:?}", waitpid(child, None).unwrap());

            unsafe {
                let mut err: i32 = 0;
                dtrace_handle = dtrace::dtrace_open(3, 0, &mut err); 
                if dtrace_handle.is_null() {
                    panic!("dtrace_open failed: {}", err);
                }

                // Option reference: https://docs.oracle.com/cd/E23824_01/html/E22973/gkzhi.html#scrolltoc
                let opt = CString::new("bufsize").unwrap();
                let val = CString::new("4096").unwrap();
                if dtrace::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_setopt(bufsize) failed: {}", err);
                }

                let opt = CString::new("aggsize").unwrap();
                let val = CString::new("4096").unwrap();
                if dtrace::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_setopt(bufsize) failed: {}", err);
                }

                // Set an aggregate interval of 1ns, so that snapshot and aggregate walking
                // always fetch new data.
                // https://github.com/apple-oss-distributions/dtrace/blob/05b1f5b12ead47eb14e4712e24a1b1a981498020/lib/libdtrace/common/dt_aggregate.c#L733
                let opt = CString::new("aggrate").unwrap();
                let val = CString::new("1ns").unwrap();
                if dtrace::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_setopt(bufsize) failed: {}", err);
                }

                // Needed for raise() to work
                let opt = CString::new("destructive").unwrap();
                if dtrace::dtrace_setopt(dtrace_handle, opt.as_ptr(), std::ptr::null()) != 0 {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_setopt(destructive) failed: {}", err);
                }

                // x16 is the syscall number
                // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/dev/dtrace/systrace.c#L156
                let program = CString::new(format!(
                    "syscall:::entry /pid == {}/ {{ @counts[uregs[16]] = count(); raise(SIGSTOP); }}",
                    //"syscall:::entry /pid == {}/ {{ @counts[probefunc] = count(); raise(SIGSTOP); }}",
                    child
                )).unwrap();
                trace!("DTrace program: {}", program.to_str().unwrap());

                let prog = dtrace::dtrace_program_strcompile(
                    dtrace_handle,
                    program.as_ptr(),
                    dtrace::dtrace_probespec_DTRACE_PROBESPEC_NAME,
                    0,
                    0,
                    std::ptr::null(),
                );
                if prog.is_null() {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_program_strcompile failed: {}", err);
                }

                let mut pip: dtrace::dtrace_proginfo_t = std::mem::zeroed();
                if dtrace::dtrace_program_exec(dtrace_handle, prog, &mut pip) != 0 {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_program_exec failed: {}", err);
                }

                if dtrace::dtrace_go(dtrace_handle) != 0 {
                    let err = dtrace::dtrace_errno(dtrace_handle);
                    panic!("dtrace_go failed: {}", err);
                }
            }

            // https://www.spaceflint.com/?p=150
            // https://sourcegraph.com/github.com/hhhaiai/decompile/-/blob/bin/radareorg_radare2/libr/debug/p/native/xnu/xnu_excthreads.c?L455:23
            let mut task_port: mach::mach_types::task_t = 0;
            let mut exception_port: mach::port::mach_port_name_t = 0;
            unsafe {
                mach_check_return(mach::traps::task_for_pid(
                    mach::traps::mach_task_self(),
                    child.into(),
                    &mut task_port,
                ))
                .unwrap();
                trace!("task_port: {}", task_port);

                mach_check_return(mach::mach_port::mach_port_allocate(
                    mach::traps::mach_task_self(),
                    mach::port::MACH_PORT_RIGHT_RECEIVE,
                    &mut exception_port,
                ))
                .unwrap();
                trace!("exception_port: {}", exception_port);

                mach_check_return(mach::mach_port::mach_port_insert_right(
                    mach::traps::mach_task_self(),
                    exception_port,
                    exception_port,
                    mach::message::MACH_MSG_TYPE_MAKE_SEND,
                ))
                .unwrap();
                mach_check_return(task_set_exception_ports(
                    task_port,
                    mach::exception_types::EXC_MASK_ALL,
                    exception_port,
                    (mach::exception_types::EXCEPTION_DEFAULT
                        | mach::exception_types::MACH_EXCEPTION_CODES) as i32,
                    //mach::thread_status::THREAD_STATE_NONE,  // causes invalid arg?
                    //mach::thread_status::x86_THREAD_STATE64,
                    //1,
                    5,  //https://github.com/apple/darwin-xnu/blob/main/osfmk/mach/arm/thread_status.h#L55
                ))
                .unwrap();
                trace!("set exception port");

                let mut req_port: mach::port::mach_port_t = 0;
                mach_check_return(mach_port_request_notification(
                    mach::traps::mach_task_self(),
                    task_port,
                    mig::MACH_NOTIFY_DEAD_NAME as i32, // steal the def from mig here
                    0,
                    exception_port,
                    mach::message::MACH_MSG_TYPE_MAKE_SEND_ONCE,
                    &mut req_port,
                ))
                .unwrap();
            }

            ptrace_attachexc(child).unwrap();
            trace!("Attached");

            loop {
                let mut req: [u8; 4096] = [0; 4096];
                let req_hdr = &mut req as *mut _ as *mut mach::message::mach_msg_header_t;
                let mut rpl: [u8; 4096] = [0; 4096];
                let rpl_hdr = &mut rpl as *mut _ as *mut mach::message::mach_msg_header_t;

                unsafe {
                    mach_check_return(mach::message::mach_msg(
                        req_hdr,
                        mach::message::MACH_RCV_MSG,
                        0,
                        4096,
                        exception_port,
                        mach::message::MACH_MSG_TIMEOUT_NONE,
                        mach::port::MACH_PORT_NULL,
                    ))
                    .unwrap();
                    trace!("Got message: {:?}", *req_hdr);

                    // Will call back into catch_mach_exception_raise
                    if !mach_exc_server(req_hdr, rpl_hdr) {
                        if (*req_hdr).msgh_id == mig::MACH_NOTIFY_DEAD_NAME as i32 {
                            info!("Child died");
                            break;
                        }

                        warn!(
                            "mach_exc_server failed: {}",
                            r_mach_error_string(
                                (*(&mut rpl as *mut _ as *mut mig::mig_reply_error_t)).RetCode
                            )
                        );
                    }

                    mach_check_return(mach::message::mach_msg(
                        rpl_hdr,
                        mach::message::MACH_SEND_MSG,
                        (*rpl_hdr).msgh_size,
                        0,
                        mach::port::MACH_PORT_NULL,
                        mach::message::MACH_MSG_TIMEOUT_NONE,
                        mach::port::MACH_PORT_NULL,
                    ))
                    .unwrap();
                }
            }

            trace!("Cleaning up");

            // TODO: close down ports
            unsafe {
                dtrace::dtrace_stop(dtrace_handle);
                dtrace::dtrace_close(dtrace_handle);
            }
        }
        ForkResult::Child => {
            target(&args.executable, &args.arguments);
        }
    }
}
