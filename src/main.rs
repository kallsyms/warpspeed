use clap::{Args, Parser, Subcommand};
use log::{error, info, trace, warn};
use mach::mach_check_return;
use nix::libc;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use prost::Message;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

use crate::mach::mig;

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/spawn.h#L62
const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;

mod dtrace;
mod mach;
mod recordable;

use recordable::{log_event::Event, trace::Target, LogEvent, Trace};

/// mRR, the macOS Record Replay Debugger
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record a trace
    Record(RecordArgs),

    /// Replay a trace
    Replay(ReplayArgs),
}

#[derive(Args)]
#[command(trailing_var_arg = true)]
struct RecordArgs {
    /// Output filename of the trace
    #[clap(required = true)]
    trace_filename: String,

    /// Target executable
    #[clap(required = true)]
    executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[derive(Args)]
struct ReplayArgs {
    /// Input filename of the trace
    #[clap(required = true)]
    trace_filename: String,
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

const BREAKPOINT_INSTRUCTION: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];

#[derive(Debug)]
struct Breakpoint {
    orig_bytes: Vec<u8>,
    single_step: bool,
}

fn inject_code(task_port: mach::mach_port_t, pc: u64, new_bytes: &[u8]) -> Vec<u8> {
    unsafe {
        // RWX pages aren't allowed, so have to make it RW, write, then RX again
        mach_check_return(mach::mach_vm_protect(
            task_port,
            pc,
            4,
            0,
            0x1 | 0x2 | 0x10, // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
        ))
        .unwrap();

        let mut orig_bytes: Vec<u8> = vec![0; 4];
        let mut copy_size: mach::mach_vm_size_t = 4;

        mach::mach_check_return(mach::mach_vm_read_overwrite(
            task_port,
            pc,
            4,
            orig_bytes.as_mut_ptr() as mach::mach_vm_address_t,
            &mut copy_size,
        ))
        .unwrap();

        mach_check_return(mach::mach_vm_write(
            task_port,
            pc,
            new_bytes.as_ptr() as mach::vm_offset_t,
            4,
        ))
        .unwrap();
        mach_check_return(mach::mach_vm_protect(
            task_port,
            pc,
            4,
            0,
            0x1 | 0x4, // VM_PROT_READ | VM_PROT_EXECUTE
        ))
        .unwrap();

        orig_bytes
    }
}

fn bp_next(
    next_log: Option<&LogEvent>,
    breakpoints: &mut HashMap<u64, Breakpoint>,
    task_port: mach::mach_port_t,
) {
    if let Some(next_log) = next_log {
        trace!("adding bp for next log at {:x}", next_log.pc);
        let next_pc = next_log.pc;
        let orig_bytes = inject_code(task_port, next_pc, &BREAKPOINT_INSTRUCTION);
        breakpoints.insert(
            next_pc,
            Breakpoint {
                orig_bytes,
                single_step: false,
            },
        );
    }
}

fn handle_replay_mach_exception_raise(
    expected_log: &LogEvent,
    next_log: Option<&LogEvent>,
    breakpoints: &mut HashMap<u64, Breakpoint>,
    exception_request: &mig::__Request__mach_exception_raise_t,
) -> bool {
    let thread_port = exception_request.thread.name;
    let task_port = exception_request.task.name;
    let exception = exception_request.exception;
    let code = exception_request.code;

    match exception {
        mach::EXC_BREAKPOINT => {
            // TODO: instead of laying down ~tracks~ breakpoints right infront of us
            // (https://media3.giphy.com/media/3oz8xtBx06mcZWoNJm/giphy.gif)
            // maybe just set all breakpoints at the start of the program?
            // then, for unhandled replays, restore the insn, single step, and reset the prior insn back to a breakpoint?
            // this would likely
            // 1) be faster (less flipping of memory perms)
            // 2) catch desync faster/at all (right now, if we don't hit the (expected) next breakpoint we may never hit another bp)
            let pc = code[1] as u64;
            trace!("handle_replay_mach_exception_raise: breakpoint at {:x}", pc);

            if let Some(bp) = breakpoints.get(&pc) {
                if bp.single_step {
                    trace!("continuing after single step");
                    inject_code(task_port, pc, &bp.orig_bytes);
                    breakpoints.remove(&pc);

                    bp_next(next_log, breakpoints, task_port);

                    return true;
                }
            }

            if pc != expected_log.pc {
                panic!("PC mismatch: {:x} != {:x}", pc, expected_log.pc);
            }

            let event_handled = match &expected_log.event {
                Some(Event::Syscall(expected_syscall)) => {
                    recordable::syscall::replay_syscall(task_port, thread_port, expected_syscall)
                }
                Some(Event::MachTrap(expected_mach_trap)) => {
                    recordable::mach_trap::replay_mach_trap(
                        task_port,
                        thread_port,
                        expected_mach_trap,
                    )
                }
                _ => panic!("Unexpected log entry: {:?}", expected_log),
            };

            if event_handled {
                // handler mutated the program state to replay the event, now bump the pc over the svc,
                // and lay down a breakpoint for the next event.
                let mut regs = mach::mrr_get_regs(thread_port);
                regs.__pc += 4;
                mach::mrr_set_regs(thread_port, regs);

                bp_next(next_log, breakpoints, task_port);
            } else {
                // replay didn't do anything, so we need to restore this (now breakpoint) instruction back to
                // it's original svc/syscall instruction and re-run it.
                // N.B. we don't just restore the insn and set the next bp, as the next bp might be the same address,
                // undoing the restore. Instead, we set a single step bp at the next insn, then proceed with setting the next bp.
                // TODO: optimize to check if next log is this same pc, and only do this single step if so.
                let orig = &breakpoints[&pc];
                inject_code(task_port, pc, orig.orig_bytes.as_slice());
                trace!("adding breakpoint for single step at pc: {:x}", pc + 4);
                let next_insn = inject_code(task_port, pc + 4, &BREAKPOINT_INSTRUCTION);
                // TODO: could we just PT_STEP?
                breakpoints.insert(
                    pc + 4,
                    Breakpoint {
                        orig_bytes: next_insn,
                        single_step: true,
                    },
                );
                return false;
            }
        }
        mach::EXC_SOFTWARE => {
            match code {
                [mach::EXC_SOFT_SIGNAL64, signum] => {
                    // should only be hit on first entry (when we're stopped at entry)
                    // TODO: handle replaying other signals
                    let signal: Signal = unsafe { std::mem::transmute(signum as i32) };
                    if signal != Signal::SIGCONT {
                        panic!("Unexpected signal in replay: {:?}", signal);
                    }

                    bp_next(next_log, breakpoints, task_port);
                }
                _ => {
                    info!("Unhandled EXC_SOFTWARE code: {:?}", code);
                }
            }
        }
        _ => {
            info!("Unhandled exception type: {}", exception);
        }
    }

    true
}

struct CStringArray {
    // I think this can be done with lifetimes and phantomdata...
    owned: Vec<CString>,
    pointers: Vec<*mut i8>,
}

impl CStringArray {
    fn new(strings: &[String]) -> CStringArray {
        let owned: Vec<CString> = strings
            .iter()
            .map(|a| CString::new(a.as_bytes()).unwrap())
            .collect();

        let mut pointers: Vec<*mut i8> = owned.iter().map(|s| s.as_ptr() as *mut i8).collect();
        pointers.push(std::ptr::null_mut());

        CStringArray { owned, pointers }
    }

    fn as_ptr(&self) -> *const *mut i8 {
        self.pointers.as_ptr()
    }
}

fn spawn_target(target: &Target) -> nix::unistd::Pid {
    unsafe {
        let mut pid: libc::pid_t = 0;

        let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
        let res = libc::posix_spawnattr_init(&mut attr);
        if res != 0 {
            panic!(
                "posix_spawnattr_init failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let res = libc::posix_spawnattr_setflags(
            &mut attr,
            (libc::POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_DISABLE_ASLR) as i16,
        );
        if res != 0 {
            panic!(
                "posix_spawnattr_setflags failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let executable = CString::new(target.path.clone()).unwrap();
        let mut all_args = vec![target.path.clone()];
        all_args.extend(target.arguments.clone());
        let argv = CStringArray::new(&all_args);
        let env = CStringArray::new(&target.environment);

        // let p: *const *mut i8 = argv.into();
        // trace!("{:?} {:?}", p, *p);

        let res = libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            std::ptr::null(),
            &attr,
            argv.as_ptr(),
            env.as_ptr(), // TODO
        );
        if res != 0 {
            panic!("posix_spawn failed: {}", std::io::Error::last_os_error());
        }

        nix::unistd::Pid::from_raw(pid)
    }
}

fn record(args: &RecordArgs) {
    let mut output = File::create(&args.trace_filename).unwrap();

    let target = Target {
        path: args.executable.clone(),
        arguments: args.arguments.clone(),
        environment: vec![], // TODO
    };

    let child = spawn_target(&target);
    info!("Child pid {}", child);

    let mut trace = Trace {
        target: Some(target),
        events: vec![],
    };

    let mut dtrace = dtrace::DTraceManager::new().unwrap();

    // Thread monitor
    // Record the new tid and the pc that the new thread is starting at.
    let program = format!(
        "/pid == {}/ {{ trace(tid); trace(uregs[R_PC]); stop(); }}",
        child
    );
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(
                Some("proc"),
                Some("mach_kernel"),
                None,
                Some("lwp-start"),
            ),
            &program,
            |_task_port, _thread_port, data| {
                let tid = data[0] as u32;
                let pc = data[1];
                Some(Event::Scheduling(recordable::scheduling::Scheduling {
                    tid,
                    event: Some(recordable::scheduling::scheduling::Event::Start(
                        recordable::scheduling::scheduling::NewThread { pc },
                    )),
                }))
            },
        )
        .unwrap();

    // Syscalls
    // arm64 syscalls can return 2 results in x0 and x1
    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/dev/arm/systemcalls.c#L518
    let program = format!(
        "/pid == {}/ {{ trace(uregs[0]); trace(uregs[1]); stop(); }}",
        child
    );
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(Some("syscall"), None, None, Some("entry")),
            &program,
            |task_port, thread_port, data| {
                let clobbered_regs: [u64; 2] = [data[0], data[1]];
                Some(Event::Syscall(recordable::syscall::record_syscall(
                    task_port,
                    thread_port,
                    clobbered_regs,
                )))
            },
        )
        .unwrap();

    // Mach Traps
    // Mach traps/syscalls only return one value in x0
    let program = format!("/pid == {}/ {{ trace(uregs[0]); stop(); }}", child);
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(Some("mach_trap"), None, None, Some("entry")),
            &program,
            |task_port, thread_port, data| {
                let clobbered_regs: [u64; 1] = [data[0]];
                Some(Event::MachTrap(recordable::mach_trap::record_mach_trap(
                    task_port,
                    thread_port,
                    clobbered_regs,
                )))
            },
        )
        .unwrap();

    // Library interception
    // Don't need to record any regs.
    // let program = format!(
    //     "pid{}:libsystem_kernel.dylib:mach_absolute_time:entry {{ stop(); }}",
    //     child
    // );
    // dtrace.register_program(&program, dtrace::ProbeDescription::new(None, None, Some("mach_absolute_time"), None), |task_port, thread_port, aggdata| {
    //     println!("mach_absolute_time");
    //     None
    // }).unwrap();

    dtrace.enable().unwrap();

    let (child_task_port, exception_port) = mach::mrr_set_exception_port(child);

    ptrace_attachexc(child).unwrap();
    trace!("Attached");

    let mut threadidx = 0;
    let mut known_threads: Vec<mach::thread_t> = mach::mrr_list_threads(child_task_port);

    // TODO: deal with forks
    loop {
        // First, suspend the child process.
        let status = mach::mach_check_return(unsafe { mach::task_suspend(child_task_port) });
        // TODO: async read from the exception port to check if the process exited
        if !status.is_ok() {
            break;
        }

        // mach port to the thread that was last running
        let last_thread = known_threads[threadidx];

        // Suspend new threads since they start running.
        let threads = mach::mrr_list_threads(child_task_port);

        let new_threads: Vec<mach::thread_t> = threads
            .iter()
            .filter(|t| !known_threads.contains(t))
            .map(|t| *t)
            .collect();
        let exited_threads: Vec<mach::thread_t> = known_threads
            .iter()
            .filter(|t| !threads.contains(t))
            .map(|t| *t)
            .collect();

        for thread in &new_threads {
            trace!("Suspending new thread: {}", *thread);
            mach::mach_check_return(unsafe { mach::thread_suspend(*thread) }).unwrap();
        }

        // Add new threads to the list of known threads
        for thread in &new_threads {
            known_threads.push(*thread);
        }
        // And remove exited threads
        for thread in &exited_threads {
            trace!("Thread exited: {}", thread);
            known_threads.retain(|t| t != thread);
        }

        if !exited_threads.contains(&last_thread) {
            // Suspend the thread that was just running
            // TODO: skip this suspend/resume if there's only 1 thread
            trace!("Suspending thread: {}", last_thread);
            mach::mach_check_return(unsafe { mach::thread_suspend(last_thread) }).unwrap();

            // Then handle any events we got from dtrace.
            let events = dtrace.dispatch(child_task_port, last_thread);
            trace!("Events: {:?}", events);
            for event in events {
                let log_entry = LogEvent {
                    pc: mach::mrr_get_regs(last_thread).__pc - 4,
                    event: Some(event),
                };
                trace!("Logging: {:?}", log_entry);
                trace.events.push(log_entry);
            }
        }

        // Switch to the next thread
        threadidx = (threadidx + 1) % known_threads.len();
        let new_thread = known_threads[threadidx];

        // And resume it
        trace!("Resuming thread: {}", new_thread);
        mach::mach_check_return(unsafe { mach::thread_resume(new_thread) }).unwrap();

        // And resume the entire task
        // (may require multiple resumes if the task was suspended by dtrace)
        let mut ti: mach::mach_task_basic_info = unsafe { std::mem::zeroed() };
        let mut n: u32 = mach::TASK_INFO_MAX as u32;
        mach::mach_check_return(unsafe {
            mach::task_info(
                child_task_port,
                mach::MACH_TASK_BASIC_INFO as u32,
                &mut ti as *mut _ as *mut i32,
                &mut n,
            )
        })
        .unwrap();

        for _ in 0..ti.suspend_count {
            mach::mach_check_return(unsafe { mach::task_resume(child_task_port) }).unwrap();
        }

        // TODO: there's got to be a way to receive an event when the child is suspended by dtrace...
        std::thread::sleep(Duration::from_millis(1));
    }

    trace!("Cleaning up");

    // TODO: close down ports? (maybe a drop impl on a mach port type?)

    output
        .write_all(prost::Message::encode_to_vec(&trace).as_slice())
        .unwrap();
}

fn replay(args: &ReplayArgs) {
    let trace_file = std::fs::read(&args.trace_filename).unwrap();
    let trace = Trace::decode(trace_file.as_slice()).unwrap();
    let mut events = trace.events.iter();

    let mut this_entry = events.next().unwrap();
    let mut next_entry = events.next();

    let child = spawn_target(&trace.target.unwrap());
    info!("Child pid {}", child);

    let (_task_port, exception_port) = mach::mrr_set_exception_port(child);

    ptrace_attachexc(child).unwrap();
    trace!("Attached");

    let mut breakpoints = HashMap::new();

    loop {
        let advance;

        let mut req_buf: [u8; 4096] = [0; 4096];
        let request_header = &mut req_buf as *mut _ as *mut mach::mach_msg_header_t;
        let mut rpl_buf: [u8; 4096] = [0; 4096];
        let reply_header = &mut rpl_buf as *mut _ as *mut mach::mach_msg_header_t;

        unsafe {
            mach::mach_check_return(mach::mach_msg(
                request_header,
                mach::MACH_RCV_MSG,
                0,
                4096,
                exception_port,
                mach::MACH_MSG_TIMEOUT_NONE,
                mach::MACH_PORT_NULL,
            ))
            .unwrap();

            match (*request_header).msgh_id {
                mach::MACH_NOTIFY_DEAD_NAME => {
                    info!("Child died");
                    break;
                }
                mig::MACH_EXCEPTION_RAISE => {
                    (*reply_header).msgh_bits =
                        (*request_header).msgh_bits & mig::MACH_MSGH_BITS_REMOTE_MASK;
                    (*reply_header).msgh_remote_port = (*request_header).msgh_remote_port;
                    (*reply_header).msgh_size =
                        std::mem::size_of::<mig::__Reply__mach_exception_raise_t>() as u32;
                    (*reply_header).msgh_local_port = mach::MACH_PORT_NULL;
                    (*reply_header).msgh_id = (*request_header).msgh_id + 100;
                    (*reply_header).msgh_voucher_port = 0;

                    let exception_request = *(request_header as *const _
                        as *const mig::__Request__mach_exception_raise_t);
                    advance = handle_replay_mach_exception_raise(
                        &this_entry,
                        next_entry,
                        &mut breakpoints,
                        &exception_request,
                    );

                    let mut exception_reply =
                        &mut rpl_buf as *mut _ as *mut mig::__Reply__mach_exception_raise_t;
                    (*exception_reply).RetCode = mach::KERN_SUCCESS;
                    (*exception_reply).NDR = mig::NDR_record;
                }
                x => {
                    error!("unexpected mach_msg number: {}", x);
                    break;
                }
            }

            mach::mach_check_return(mach::mach_msg(
                reply_header,
                mach::MACH_SEND_MSG,
                (*reply_header).msgh_size,
                0,
                mach::MACH_PORT_NULL,
                mach::MACH_MSG_TIMEOUT_NONE,
                mach::MACH_PORT_NULL,
            ))
            .unwrap();
        }

        if advance {
            if next_entry.is_none() {
                break;
            }

            this_entry = next_entry.unwrap();
            next_entry = events.next();
        }
    }

    trace!("Cleaning up");
}

fn main() {
    let args = Cli::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    match args.command {
        Command::Record(args) => {
            record(&args);
        }
        Command::Replay(args) => {
            replay(&args);
        }
    }
}
