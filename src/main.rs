use clap::Parser;
use log::{debug, error, info, trace, warn};
use nix::libc;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{execve, fork, getpid, sleep, ForkResult};
use std::boxed::Box;
use std::default;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;

#[link(name = "mach_excServer", kind = "static")]
extern "C" {
    fn mach_exc_server(
        request: *mut mach::mach_msg_header_t,
        reply: *mut mach::mach_msg_header_t,
    ) -> bool;
}

const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;

mod dtrace;
mod mach;
mod mig;

mod syscall;

/// mRR, the macOS Record Replay Debugger
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, trailing_var_arg=true)]
struct Args {
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[clap(required = true)]
    output_filename: String,

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
    port: mach::mach_port_t,
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

static mut global_child: nix::unistd::Pid = nix::unistd::Pid::from_raw(0);
static mut dtrace_handle: *mut dtrace::dtrace_hdl = std::ptr::null_mut();
static mut output: Option<Box<dyn std::io::Write>> = None;

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise(
    exception_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    task_port: mach::mach_port_t,
    exception: mach::exception_type_t,
    code: mach::exception_data_t,
    code_count: mach::mach_msg_type_number_t,
) -> mach::kern_return_t {
    let codes = unsafe { std::slice::from_raw_parts(code, (code_count + 1) as usize) };
    // trace!(
    //     "mach_exception_raise: {:?} {:?} {:?} {:?} {:?} {:?} ({:?})",
    //     exception_port,
    //     thread_port,
    //     task_port,
    //     exception,
    //     code,
    //     code_count,
    //     codes
    // );

    match exception {
        mach::EXC_SOFTWARE => {
            match codes {
                [mach::EXC_SOFT_SIGNAL, _, signum] => {
                    let signal: Signal;
                    unsafe {
                        signal = std::mem::transmute(*signum);
                    }
                    trace!("EXC_SOFT_SIGNAL: {}", signal);

                    let mut regs: [u64; 2] = [0; 2];

                    unsafe {
                        if dtrace::dtrace_aggregate_snap(dtrace_handle) == -1 {
                            warn!("dtrace_aggregate_snap failed: {}", CStr::from_ptr(dtrace::dtrace_errmsg(dtrace_handle, dtrace::dtrace_errno(dtrace_handle))).to_str().unwrap());
                        }
                        let closure = |agg: *const dtrace::dtrace_aggdata_t| {
                            let desc = *((*agg).dtada_desc);
                            let records: &[dtrace::dtrace_recdesc] = std::slice::from_raw_parts(&(*(*agg).dtada_desc).dtagd_rec as *const dtrace::dtrace_recdesc_t, (desc.dtagd_nrecs) as usize);
                            let mut vals: Vec<u64> = vec![];
                            for rec in records {
                                let ptr = ((*agg).dtada_data).offset(rec.dtrd_offset as isize);
                                match rec.dtrd_size {
                                    1 => vals.push(*(ptr as *const u8) as u64),
                                    2 => vals.push(*(ptr as *const u16) as u64),
                                    4 => vals.push(*(ptr as *const u32) as u64),
                                    8 => vals.push(*(ptr as *const u64)),
                                    _ => error!("dtrace agg: unhandled size: {}", rec.dtrd_size),
                                }
                            }
                            let aggname = CStr::from_ptr(desc.dtagd_name).to_str().unwrap();
                            //trace!("dtrace agg {} vals: {:?}", aggname, vals);
                            if vals[2] != 0 {
                                match aggname {
                                    "r0" => regs[0] = vals[1],
                                    "r1" => regs[1] = vals[1],
                                    _ => error!("dtrace agg: unhandled name: {}", aggname),
                                }
                            }
                            dtrace::DTRACE_AGGWALK_NEXT as i32
                        };
                        dtrace_aggregate_walk_cb(dtrace_handle, closure);
                        dtrace::dtrace_aggregate_clear(dtrace_handle);
                    }

                    if let Some(sc) = syscall::record_syscall(task_port, thread_port, regs) {
                        trace!("syscall: {:?}", sc);
                        unsafe {
                            serde_json::to_writer_pretty(output.as_mut().unwrap(), &sc).unwrap();
                        }
                    };


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
    return mach::KERN_SUCCESS;
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise_state(
    _exception_port: mach::mach_port_t,
    _exception: mach::exception_type_t,
    _code: mach::exception_data_t,
    _code_count: mach::mach_msg_type_number_t,
    _flavor: *mut mach::thread_state_flavor_t,
    _old_state: mach::thread_state_t,
    _old_state_count: mach::mach_msg_type_number_t,
    _new_state: mach::thread_state_t,
    _new_state_count: *mut mach::mach_msg_type_number_t,
) -> mach::kern_return_t {
    error!("Unexpected mach_exception_raise_state");
    return mach::MACH_RCV_INVALID_TYPE;
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise_state_identity(
    _exception_port: mach::mach_port_t,
    _thread_port: mach::mach_port_t,
    _task_port: mach::mach_port_t,
    _exception: mach::exception_type_t,
    _code: mach::exception_data_t,
    _code_count: mach::mach_msg_type_number_t,
    _flavor: *mut mach::thread_state_flavor_t,
    _old_state: mach::thread_state_t,
    _old_state_count: mach::mach_msg_type_number_t,
    _new_state: mach::thread_state_t,
    _new_state_count: *mut mach::mach_msg_type_number_t,
) -> mach::kern_return_t {
    error!("Unexpected mach_exception_raise_state_identity");
    return mach::MACH_RCV_INVALID_TYPE;
}

fn main() {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();
    
    unsafe {
        output = Some(Box::new(File::create(args.output_filename).unwrap()));
    }

    let child = unsafe {
        let mut pid: libc::pid_t = 0;

        let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
        let res = libc::posix_spawnattr_init(&mut attr);
        if res != 0 {
            error!("posix_spawnattr_init failed: {}", std::io::Error::last_os_error());
            return;
        }

        let res = libc::posix_spawnattr_setflags(
            &mut attr,
            (libc::POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_DISABLE_ASLR) as i16,
        );
        if res != 0 {
            error!("posix_spawnattr_setflags failed: {}", std::io::Error::last_os_error());
            return;
        }

        let executable = CString::new(args.executable).unwrap();
        let mut cargs_owned: Vec<CString> = vec![executable.clone()];
        cargs_owned.extend(args.arguments.iter().map(|a| CString::new(a.as_bytes()).unwrap()));
        let mut argv: Vec<*mut i8> = cargs_owned.iter().map(|s| s.as_ptr() as *mut i8).collect();
        argv.push(std::ptr::null_mut());
        let env: Vec<*mut i8> = vec![std::ptr::null_mut()]; // TODO

        let res = libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            std::ptr::null(),
            &attr,
            argv.as_ptr(),
            env.as_ptr(),  // TODO
        );
        if res != 0 {
            error!("posix_spawn failed: {}", std::io::Error::last_os_error());
            return;
        }
        
        nix::unistd::Pid::from_raw(pid)
    };

    unsafe {
        global_child = child;
    }
    info!("Child pid {}", child);

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
            "syscall:::entry /pid == {}/ {{ @r0[uregs[0]] = count(); @r1[uregs[1]] = count(); raise(SIGSTOP); }}",
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
    let mut task_port: mach::task_t = 0;
    let mut exception_port: mach::mach_port_name_t = 0;
    unsafe {
        mach::mach_check_return(mach::task_for_pid(
            mach::mach_task_self(),
            child.into(),
            &mut task_port,
        ))
        .unwrap();
        trace!("task_port: {}", task_port);

        mach::mach_check_return(mach::mach_port_allocate(
            mach::mach_task_self(),
            mach::MACH_PORT_RIGHT_RECEIVE,
            &mut exception_port,
        ))
        .unwrap();
        trace!("exception_port: {}", exception_port);

        mach::mach_check_return(mach::mach_port_insert_right(
            mach::mach_task_self(),
            exception_port,
            exception_port,
            mach::MACH_MSG_TYPE_MAKE_SEND,
        ))
        .unwrap();
        mach::mach_check_return(mach::task_set_exception_ports(
            task_port,
            mach::EXC_MASK_ALL,
            exception_port,
            (mach::EXCEPTION_DEFAULT
                | mach::MACH_EXCEPTION_CODES) as i32,
            mach::THREAD_STATE_NONE,  // Why does setting ARM_THREAD_STATE not cause us to go to the state handler?
        ))
        .unwrap();
        trace!("set exception port");

        let mut req_port: mach::mach_port_t = 0;
        mach::mach_check_return(mach::mach_port_request_notification(
            mach::mach_task_self(),
            task_port,
            mach::MACH_NOTIFY_DEAD_NAME,
            0,
            exception_port,
            mach::MACH_MSG_TYPE_MAKE_SEND_ONCE,
            &mut req_port,
        ))
        .unwrap();
    }

    ptrace_attachexc(child).unwrap();
    trace!("Attached");

    loop {
        let mut req: [u8; 4096] = [0; 4096];
        let req_hdr = &mut req as *mut _ as *mut mach::mach_msg_header_t;
        let mut rpl: [u8; 4096] = [0; 4096];
        let rpl_hdr = &mut rpl as *mut _ as *mut mach::mach_msg_header_t;

        unsafe {
            mach::mach_check_return(mach::mach_msg(
                req_hdr,
                mach::MACH_RCV_MSG,
                0,
                4096,
                exception_port,
                mach::MACH_MSG_TIMEOUT_NONE,
                mach::MACH_PORT_NULL,
            ))
            .unwrap();
            //trace!("Got message: {:?}", *req_hdr);

            // Will call back into catch_mach_exception_raise
            if !mach_exc_server(req_hdr, rpl_hdr) {
                if (*req_hdr).msgh_id == mach::MACH_NOTIFY_DEAD_NAME {
                    info!("Child died");
                    break;
                }

                warn!(
                    "mach_exc_server failed: {}",
                    mach::r_mach_error_string(
                        (*(&mut rpl as *mut _ as *mut mig::mig_reply_error_t)).RetCode
                    )
                );
            }

            mach::mach_check_return(mach::mach_msg(
                rpl_hdr,
                mach::MACH_SEND_MSG,
                (*rpl_hdr).msgh_size,
                0,
                mach::MACH_PORT_NULL,
                mach::MACH_MSG_TIMEOUT_NONE,
                mach::MACH_PORT_NULL,
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
