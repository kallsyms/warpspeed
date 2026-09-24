use appbox::applevisor as av;
use appbox::gdb::{GdbCommand, GdbResponse};
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::vm::{VmManager, VmRunResult};
use anyhow::{Context, Result};
use log::{debug, info};
use prost::Message;
use std::path::PathBuf;

use crate::cli;
use crate::recordable::Trace;
use crate::warpspeed;

fn handle_gdb_command(
    cmd: GdbCommand,
    vm: &mut VmManager,
    response_sender: &std::sync::mpsc::Sender<GdbResponse>,
) {
    appbox::gdb::handle_command(cmd, vm, response_sender)
}

enum Attempt {
    Done,
    /// Missed the preemption at this event, so must start over. Carries the debugger's
    /// breakpoints, which go with the VM.
    Missed { event: usize, breakpoints: Vec<u64> },
}

pub fn replay(args: &cli::ReplayArgs) -> Result<()> {
    let trace_file = std::fs::read(&args.trace_filename)?;
    let trace = Trace::decode(trace_file.as_slice())?;
    debug!("Loaded trace with {} events", trace.events.len());

    // GDB server channels
    let (command_sender, command_receiver) = std::sync::mpsc::channel();
    let (response_sender, response_receiver) = std::sync::mpsc::channel();

    let notification_sender = if let Some(port) = args.gdb_port {
        Some(appbox::gdb::start_gdb_server(
            port,
            command_sender,
            response_receiver,
            None,
            appbox::gdb::GdbFeatures {
                reverse_continue: true,
                reverse_step: true,
                ..Default::default()
            },
        )?)
    } else {
        None
    };

    // Finding where a thread was preempted can occasionally overshoot; replay then starts over,
    // finding that one more carefully.
    let mut plan = warpspeed::ReplayPlan::default();
    // For testing restarts: the first attempt assumes the guest runs this slowly, so it
    // overshoots.
    if let Some(rate) = std::env::var("WARPSPEED_TEST_FIRST_ATTEMPT_INSTRUCTIONS_PER_NS")
        .ok()
        .and_then(|rate| rate.parse().ok())
    {
        plan.max_instructions_per_ns = rate;
    }
    let mut first = true;
    let mut breakpoints = Vec::new();
    loop {
        match replay_attempt(
            args,
            &trace,
            &plan,
            first,
            &breakpoints,
            &command_receiver,
            &response_sender,
            &notification_sender,
        )? {
            Attempt::Done => return Ok(()),
            Attempt::Missed {
                event,
                breakpoints: set,
            } => {
                breakpoints = set;
                info!("Restarting replay to find the preemption at event {event} carefully");
                plan.careful.insert(event);
                plan.quiet_until = plan.quiet_until.max(event);
                plan.max_instructions_per_ns = warpspeed::ReplayPlan::default().max_instructions_per_ns;
                first = false;
            }
        }
    }
}

fn replay_attempt(
    args: &cli::ReplayArgs,
    trace: &Trace,
    plan: &warpspeed::ReplayPlan,
    first: bool,
    breakpoints: &[u64],
    command_receiver: &std::sync::mpsc::Receiver<GdbCommand>,
    response_sender: &std::sync::mpsc::Sender<GdbResponse>,
    notification_sender: &Option<std::sync::mpsc::Sender<appbox::gdb::GdbNotification>>,
) -> Result<Attempt> {
    let target = trace.target.clone().context("trace missing target")?;

    let mut warpspeed = warpspeed::Warpspeed::new(trace.clone(), warpspeed::Mode::Replay)?;
    warpspeed.set_replay_plan(plan.clone());

    let mut vm = VmManager::new()?;

    let mut loader = appbox::loader::load_macho(
        &mut vm,
        &PathBuf::from(target.path),
        target.arguments,
        target.environment,
    )
    ?;

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)
        ?;
    vm.count_instructions()?;

    // Store initial state for backward execution
    let initial_pc = loader.entry_point;
    let initial_sp = loader.stack_pointer;

    if args.gdb_port.is_some() {
        if args.gdb_wait && first {
            info!("Waiting for GDB connection...");
            loop {
                if let Ok(cmd) = command_receiver.recv() {
                    match cmd {
                        appbox::gdb::GdbCommand::Continue => break,
                        appbox::gdb::GdbCommand::Kill => return Ok(Attempt::Done),
                        _ => appbox::gdb::handle_command(cmd, &mut vm, response_sender),
                    }
                }
            }
        }
    }

    let mut single_step_breakpoint: Option<u64> = None;

    // After a restart, the debugger's breakpoints only go back in once replay has caught up with
    // where the previous attempt was: before that, the debugger has already seen everything.
    let mut breakpoints_installed = false;

    let final_exit;
    loop {
        let catching_up = warpspeed.catching_up();
        if !catching_up && !breakpoints_installed {
            for &addr in breakpoints {
                vm.hooks.add_breakpoint(addr, &mut vm.vma)?;
            }
            breakpoints_installed = true;
        }

        let run_result = if warpspeed.preemption_next() {
            match warpspeed.replay_preemption(&mut vm)? {
                warpspeed::PreemptionReplay::Replayed(ExitKind::Continue) => continue,
                warpspeed::PreemptionReplay::Replayed(exit) => {
                    final_exit = exit;
                    break;
                }
                warpspeed::PreemptionReplay::Stopped(run_result) => run_result,
                warpspeed::PreemptionReplay::Missed { event } => {
                    let mut breakpoints = if breakpoints_installed {
                        vm.hooks.breakpoints()
                    } else {
                        breakpoints.to_vec()
                    };
                    breakpoints.retain(|&addr| Some(addr) != single_step_breakpoint);
                    warpspeed.release_guest();
                    drop(loader);
                    drop(vm);
                    return Ok(Attempt::Missed { event, breakpoints });
                }
            }
        } else {
            vm.run()?
        };

        // The debugger waits until replay has caught up.
        while let Some(cmd) = (!catching_up)
            .then(|| command_receiver.try_recv().ok())
            .flatten()
        {
            match cmd {
                appbox::gdb::GdbCommand::Continue => {
                    // Remove single step breakpoint if it exists
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }
                    break;
                }

                appbox::gdb::GdbCommand::Step => {
                    // Get current instruction to determine next PC
                    let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                    let mut insn_bytes = [0; 4];
                    vm.vma.read(pc, &mut insn_bytes)?;

                    // Remove previous single step breakpoint if it exists
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }

                    // For now, assume next instruction is at PC + 4
                    // TODO: Enhance this to handle branches properly by using instruction emulation
                    let next_pc = pc + 4;

                    // Set new single step breakpoint
                    vm.hooks.add_breakpoint(next_pc, &mut vm.vma)?;
                    single_step_breakpoint = Some(next_pc);
                    break;
                }

                appbox::gdb::GdbCommand::Kill => {
                    return Ok(Attempt::Done);
                }

                appbox::gdb::GdbCommand::BackwardsStep => {
                    // Reset VM to initial state
                    vm.vcpu.set_reg(av::Reg::PC, initial_pc)?;
                    vm.vcpu.set_sys_reg(av::SysReg::SP_EL0, initial_sp)?;

                    // Reset warpspeed to beginning of trace
                    warpspeed =
                        warpspeed::Warpspeed::new(trace.clone(), warpspeed::Mode::Replay)?;

                    // Remove any existing single step breakpoint
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }

                    // Set breakpoint at PC - 4 (previous instruction)
                    if initial_pc >= 4 {
                        let prev_pc = initial_pc - 4;
                        vm.hooks.add_breakpoint(prev_pc, &mut vm.vma)?;
                        single_step_breakpoint = Some(prev_pc);
                    }
                    break;
                }

                appbox::gdb::GdbCommand::BackwardsContinue => {
                    // Reset VM to initial state
                    vm.vcpu.set_reg(av::Reg::PC, initial_pc)?;
                    vm.vcpu.set_sys_reg(av::SysReg::SP_EL0, initial_sp)?;

                    // Reset warpspeed to beginning of trace
                    warpspeed =
                        warpspeed::Warpspeed::new(trace.clone(), warpspeed::Mode::Replay)?;

                    // Remove any existing single step breakpoint
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }
                    break;
                }

                _ => {
                    handle_gdb_command(cmd, &mut vm, response_sender);
                }
            }
        }

        // https://github.com/kallsyms/hyperpom/blob/a1dd1aebd8f306bb8549595d9d1506c2a361f0d7/src/core.rs#L1535
        let exit = match run_result {
            VmRunResult::Svc => warpspeed.trap_handler(&mut vm, &loader)?,
            // Only preemption replay (above) arms the timer or sets hardware breakpoints.
            VmRunResult::Timer => ExitKind::Continue,
            VmRunResult::HardwareBreakpoint | VmRunResult::Step => {
                ExitKind::Crash("unexpected debug exception".to_string())
            }
            VmRunResult::Brk => {
                let pc = vm.vcpu.get_reg(av::Reg::PC)?;

                // Check if this is our single step breakpoint
                if Some(pc) == single_step_breakpoint {
                    println!("Single step completed at {:#x}", pc);
                    // Remove the single step breakpoint
                    vm.hooks.remove_breakpoint(pc, &mut vm.vma)?;
                    single_step_breakpoint = None;
                    // Don't handle as normal breakpoint since we removed it
                    ExitKind::Continue
                } else if notification_sender.is_none() {
                    // No debugger set any breakpoints, so the guest trapped (e.g. abort()).
                    log::error!("Guest trapped (brk) at {:#x}", pc);
                    warpspeed::log_guest_stack(&vm, &loader);
                    ExitKind::Crash("guest trap (brk)".to_string())
                } else {
                    println!("Breakpoint hit at {:#x}", pc);
                    ExitKind::Continue
                }
            }
            VmRunResult::Other(exit_info) => match exit_info.reason {
                av::ExitReason::EXCEPTION => {
                    match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                        ExceptionClass::InsAbortLowerEl => {
                            let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                            println!("Instruction Abort (Lower EL) at {:#x}", pc);

                            // Send SIGSEGV signal to GDB to indicate fault
                            if let Some(sender) = notification_sender {
                                appbox::gdb::send_sigsegv(sender);
                            }

                            // Enter GDB evaluation loop for system state inspection
                            loop {
                                if let Ok(cmd) = command_receiver.recv() {
                                    match cmd {
                                        appbox::gdb::GdbCommand::Continue => break,
                                        appbox::gdb::GdbCommand::Kill => return Ok(Attempt::Done),
                                        appbox::gdb::GdbCommand::BackwardsStep => {
                                            // Reset VM to initial state
                                            vm.vcpu.set_reg(av::Reg::PC, initial_pc)?;
                                            vm.vcpu
                                                .set_sys_reg(av::SysReg::SP_EL0, initial_sp)
                                                ?;

                                            // Reset warpspeed to beginning of trace
                                            warpspeed = warpspeed::Warpspeed::new(
                                                trace.clone(),
                                                warpspeed::Mode::Replay,
                                            )?;

                                            // Remove any existing single step breakpoint
                                            if let Some(addr) = single_step_breakpoint.take() {
                                                let _ =
                                                    vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                                            }

                                            // Set breakpoint at PC - 4 (previous instruction)
                                            if initial_pc >= 4 {
                                                let prev_pc = initial_pc - 4;
                                                vm.hooks
                                                    .add_breakpoint(prev_pc, &mut vm.vma)
                                                    ?;
                                                single_step_breakpoint = Some(prev_pc);
                                            }
                                            break;
                                        }
                                        appbox::gdb::GdbCommand::BackwardsContinue => {
                                            // Reset VM to initial state
                                            vm.vcpu.set_reg(av::Reg::PC, initial_pc)?;
                                            vm.vcpu
                                                .set_sys_reg(av::SysReg::SP_EL0, initial_sp)
                                                ?;

                                            // Reset warpspeed to beginning of trace
                                            warpspeed = warpspeed::Warpspeed::new(
                                                trace.clone(),
                                                warpspeed::Mode::Replay,
                                            )?;

                                            // Remove any existing single step breakpoint
                                            if let Some(addr) = single_step_breakpoint.take() {
                                                let _ =
                                                    vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                                            }
                                            break;
                                        }
                                        _ => handle_gdb_command(cmd, &mut vm, response_sender),
                                    }
                                }
                            }

                            // Always crash after inspection - no recovery possible
                            ExitKind::Crash("Instruction Abort".to_string())
                        }
                        _ => {
                            return Err(
                                ExceptionError::UnimplementedException(
                                    exit_info.exception.syndrome,
                                )
                                .into(),
                            );
                        }
                    }
                }
                av::ExitReason::CANCELED => ExitKind::Timeout,
                av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
                av::ExitReason::UNKNOWN => {
                    let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                    panic!("Vcpu exited unexpectedly at address {:#x}", pc);
                }
            },
        };

        match exit {
            ExitKind::Continue => continue,
            ExitKind::Exec(request) => {
                // Breakpoints went with the old image.
                single_step_breakpoint = None;
                (vm, loader) = warpspeed.exec(vm, loader, &request)?;
            }
            exit => {
                final_exit = exit;
                break;
            }
        };
    }

    if let ExitKind::Crash(reason) = final_exit {
        anyhow::bail!("guest crashed: {reason}");
    }
    Ok(Attempt::Done)
}
