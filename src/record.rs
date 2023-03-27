use log::{error, info, trace, warn};
use std::fs::File;
use std::io::Write;
use std::time::Duration;

use crate::cli;
use crate::dtrace;
use crate::kdebug;
use crate::mach;
use crate::recordable;
use crate::util;

use mach::mach_check_return;
use recordable::{log_event::Event, trace::Target, LogEvent, Trace};

pub fn record(args: &cli::RecordArgs) {
    let mut output = File::create(&args.trace_filename).unwrap();

    let target = Target {
        path: args.executable.clone(),
        arguments: args.arguments.clone(),
        environment: vec![], // TODO
    };

    let child = util::spawn_target(&target);
    info!("Child pid {}", child);

    let mut trace = Trace {
        target: Some(target),
        events: vec![],
    };

    let mut dtrace = dtrace::DTraceManager::new().unwrap();
    kdebug::init(child).unwrap();
    kdebug::enable().unwrap();

    // Thread monitor
    // Record the new tid and the pc that the new thread is starting at.
    let program = format!("/pid == {}/ {{ trace(uregs[R_PC]); stop(); }}", child);
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(
                Some("proc"),
                Some("mach_kernel"),
                None,
                Some("lwp-start"),
            ),
            &program,
            |_task_port, thread_port, data| {
                let pc = data[0];
                Some(Event::Scheduling(recordable::scheduling::Scheduling {
                    tid: thread_port,
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
        "/pid == {}/ {{ self->x0 = uregs[0]; self->x1 = uregs[1]; }}",
        child
    );
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(Some("syscall"), None, None, Some("entry")),
            &program,
            |_task_port, _thread_port, _data| None,
        )
        .unwrap();

    let program = format!(
        "/pid == {}/ {{ trace(self->x0); trace(self->x1); stop();}}",
        child
    );
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(Some("syscall"), None, None, Some("return")),
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
    let program = format!("/pid == {}/ {{ self->x0 = uregs[0]; }}", child);
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(Some("mach_trap"), None, None, Some("entry")),
            &program,
            |_task_port, _thread_port, _data| None,
        )
        .unwrap();

    let program = format!("/pid == {}/ {{ trace(self->x0); stop(); }}", child);
    dtrace
        .register_program(
            dtrace::ProbeDescription::new(Some("mach_trap"), None, None, Some("return")),
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

    let (child_task_port, _exception_port) = mach::mrr_set_exception_port(child);

    util::ptrace_attachexc(child).unwrap();
    trace!("Attached");

    let mut threadidx = 0;
    let mut known_threads: Vec<mach::thread_t> = mach::mrr_list_threads(child_task_port);

    // TODO: deal with forks
    loop {
        // First, suspend the child process.
        let status = mach_check_return(unsafe { mach::task_suspend(child_task_port) });
        // TODO: async read from the exception port to check if the process exited
        if status.is_err() {
            break;
        }

        // mach port to the thread that was last running
        let last_thread = known_threads[threadidx];

        // Suspend new threads since they start running.
        let threads = mach::mrr_list_threads(child_task_port);

        let new_threads: Vec<mach::thread_t> = threads
            .iter()
            .filter(|t| !known_threads.contains(t))
            .copied()
            .collect();
        let exited_threads: Vec<mach::thread_t> = known_threads
            .iter()
            .filter(|t| !threads.contains(t))
            .copied()
            .collect();

        for thread in &new_threads {
            trace!("Suspending new thread: {}", *thread);
            mach_check_return(unsafe { mach::thread_suspend(*thread) }).unwrap();
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
            mach_check_return(unsafe { mach::thread_suspend(last_thread) }).unwrap();

            // Then handle any events we got from dtrace.
            let events = dtrace.dispatch(child_task_port, last_thread);
            trace!("Events: {:?}", events);
            for event in events {
                let log_entry = LogEvent {
                    pc: mach::mrr_get_regs(last_thread).__pc - 4,
                    register_state: mach::mrr_get_regs(last_thread).__x.to_vec(),
                    event: Some(event),
                };
                trace!("Logging: {:?}", log_entry);
                trace.events.push(log_entry);
            }
        }

        // Switch to the next thread
        threadidx = (threadidx + 1) % known_threads.len();
        let new_thread = known_threads[threadidx];

        if new_thread != last_thread {
            trace.events.push(LogEvent {
                pc: mach::mrr_get_regs(last_thread).__pc - 4,
                register_state: mach::mrr_get_regs(last_thread).__x.to_vec(),
                event: Some(Event::Scheduling(recordable::scheduling::Scheduling {
                    tid: last_thread,
                    event: Some(recordable::scheduling::scheduling::Event::Switch(
                        recordable::scheduling::scheduling::SwitchCurrent {
                            new_tid: new_thread,
                        },
                    )),
                })),
            });
        }

        // And resume it
        trace!("Resuming thread: {}", new_thread);
        mach_check_return(unsafe { mach::thread_resume(new_thread) }).unwrap();

        // And resume the entire task
        // (may require multiple resumes if the task was suspended by dtrace)
        let mut ti: mach::mach_task_basic_info = unsafe { std::mem::zeroed() };
        let mut n: u32 = mach::TASK_INFO_MAX as u32;
        mach_check_return(unsafe {
            mach::task_info(
                child_task_port,
                mach::MACH_TASK_BASIC_INFO as u32,
                &mut ti as *mut _ as *mut i32,
                &mut n,
            )
        })
        .unwrap();

        for _ in 0..ti.suspend_count {
            mach_check_return(unsafe { mach::task_resume(child_task_port) }).unwrap();
        }

        trace!("{:?}", kdebug::read());
    }

    trace!("Cleaning up");

    kdebug::disable().unwrap();

    // TODO: close down ports? (maybe a drop impl on a mach port type?)

    output
        .write_all(prost::Message::encode_to_vec(&trace).as_slice())
        .unwrap();
}
