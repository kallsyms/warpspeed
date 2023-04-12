use log::{error, info, trace, warn};
use nix::sys::signal::Signal;
use prost::Message;
use std::collections::HashMap;

use crate::cli;
use crate::mach;
use crate::mach::{mach_check_return, mig};
use crate::recordable;
use crate::recordable::{log_event::Event, LogEvent, Trace};
use crate::util;

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

        mach_check_return(mach::mach_vm_read_overwrite(
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
            trace!("Child breakpoint at {:x}", pc);

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
                panic!(
                    "PC mismatch: current {:x} != expected {:x}",
                    pc, expected_log.pc
                );
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
                // TODO: scheduling
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
                    trace!("Child received signal: {}", signum);
                    let signal: Signal = unsafe { std::mem::transmute(signum as i32) };
                    if signal != Signal::SIGSTOP {
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

pub fn replay(args: &cli::ReplayArgs) {
    let trace_file = std::fs::read(&args.trace_filename).unwrap();
    let trace = Trace::decode(trace_file.as_slice()).unwrap();
    let mut events = trace.events.iter();

    let mut this_entry = events.next().unwrap();
    let mut next_entry = events.next();

    let child = util::spawn_target(&trace.target.unwrap());
    info!("Child pid {}", child);

    let (task_port, exception_port) = mach::mrr_set_exception_port(child);

    util::ptrace_attachexc(child).unwrap();
    trace!("Attached");

    let mut breakpoints = HashMap::new();
    //bp_next(Some(this_entry), &mut breakpoints, task_port);

    loop {
        let advance;

        let mut req_buf: [u8; 4096] = [0; 4096];
        let request_header = &mut req_buf as *mut _ as *mut mach::mach_msg_header_t;
        let mut rpl_buf: [u8; 4096] = [0; 4096];
        let reply_header = &mut rpl_buf as *mut _ as *mut mach::mach_msg_header_t;

        unsafe {
            mach_check_return(mach::mach_msg(
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
                        this_entry,
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

            mach_check_return(mach::mach_msg(
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
