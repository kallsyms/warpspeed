use appbox::applevisor as av;
use appbox::gdb::{GdbCommand, GdbResponse};
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::vm::VmManager;
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

pub fn replay(args: &cli::ReplayArgs) {
    let trace_file = std::fs::read(&args.trace_filename).unwrap();
    let trace = Trace::decode(trace_file.as_slice()).unwrap();
    debug!("Loaded trace with {} events", trace.events.len());
    let target = trace.target.clone().unwrap();

    let mut warpspeed = warpspeed::Warpspeed::new(trace.clone(), warpspeed::Mode::Replay);

    let mut vm = VmManager::new().unwrap();

    let loader = appbox::loader::load_macho(
        &mut vm,
        &PathBuf::from(target.path),
        target.arguments,
        target.environment,
    )
    .unwrap();

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point).unwrap();
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)
        .unwrap();

    // Store initial state for backward execution
    let initial_pc = loader.entry_point;
    let initial_sp = loader.stack_pointer;

    // GDB server channels
    let (command_sender, command_receiver) = std::sync::mpsc::channel();
    let (response_sender, response_receiver) = std::sync::mpsc::channel();

    let notification_sender = if let Some(port) = args.gdb_port {
        Some(
            appbox::gdb::start_gdb_server(
                port,
                command_sender,
                response_receiver,
                None,
                appbox::gdb::GdbFeatures {
                    reverse_continue: true,
                    reverse_step: true,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
    } else {
        None
    };

    if args.gdb_port.is_some() {
        if args.gdb_wait {
            info!("Waiting for GDB connection...");
            loop {
                if let Ok(cmd) = command_receiver.recv() {
                    match cmd {
                        appbox::gdb::GdbCommand::Continue => break,
                        appbox::gdb::GdbCommand::Kill => return,
                        _ => appbox::gdb::handle_command(cmd, &mut vm, &response_sender),
                    }
                }
            }
        }
    }

    let mut single_step_breakpoint: Option<u64> = None;

    loop {
        vm.vcpu.run().unwrap();

        while let Ok(cmd) = command_receiver.try_recv() {
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
                    let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();
                    let mut insn_bytes = [0; 4];
                    vm.vma.read(pc, &mut insn_bytes).unwrap();

                    // Remove previous single step breakpoint if it exists
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }

                    // For now, assume next instruction is at PC + 4
                    // TODO: Enhance this to handle branches properly by using instruction emulation
                    let next_pc = pc + 4;

                    // Set new single step breakpoint
                    vm.hooks.add_breakpoint(next_pc, &mut vm.vma).unwrap();
                    single_step_breakpoint = Some(next_pc);
                    break;
                }

                appbox::gdb::GdbCommand::Kill => {
                    return;
                }

                appbox::gdb::GdbCommand::BackwardsStep => {
                    // Reset VM to initial state
                    vm.vcpu.set_reg(av::Reg::PC, initial_pc).unwrap();
                    vm.vcpu.set_sys_reg(av::SysReg::SP_EL0, initial_sp).unwrap();

                    // Reset warpspeed to beginning of trace
                    warpspeed = warpspeed::Warpspeed::new(trace.clone(), warpspeed::Mode::Replay);

                    // Remove any existing single step breakpoint
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }

                    // Set breakpoint at PC - 4 (previous instruction)
                    if initial_pc >= 4 {
                        let prev_pc = initial_pc - 4;
                        vm.hooks.add_breakpoint(prev_pc, &mut vm.vma).unwrap();
                        single_step_breakpoint = Some(prev_pc);
                    }
                    break;
                }

                appbox::gdb::GdbCommand::BackwardsContinue => {
                    // Reset VM to initial state
                    vm.vcpu.set_reg(av::Reg::PC, initial_pc).unwrap();
                    vm.vcpu.set_sys_reg(av::SysReg::SP_EL0, initial_sp).unwrap();

                    // Reset warpspeed to beginning of trace
                    warpspeed = warpspeed::Warpspeed::new(trace.clone(), warpspeed::Mode::Replay);

                    // Remove any existing single step breakpoint
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }
                    break;
                }

                _ => {
                    handle_gdb_command(cmd, &mut vm, &response_sender);
                }
            }
        }

        // https://github.com/kallsyms/hyperpom/blob/a1dd1aebd8f306bb8549595d9d1506c2a361f0d7/src/core.rs#L1535
        let exit_info = vm.vcpu.get_exit_info();
        let exit = match exit_info.reason {
            av::ExitReason::EXCEPTION => {
                match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                    ExceptionClass::HvcA64 => warpspeed
                        .trap_handler(&mut vm.vcpu, &mut vm.vma, &loader)
                        .unwrap(),
                    ExceptionClass::BrkA64 => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();

                        // Check if this is our single step breakpoint
                        if Some(pc) == single_step_breakpoint {
                            println!("Single step completed at {:#x}", pc);
                            // Remove the single step breakpoint
                            vm.hooks.remove_breakpoint(pc, &mut vm.vma).unwrap();
                            single_step_breakpoint = None;
                            // Don't handle as normal breakpoint since we removed it
                            ExitKind::Continue
                        } else {
                            println!("Breakpoint hit at {:#x}", pc);
                            ExitKind::Continue
                        }
                    }
                    ExceptionClass::InsAbortLowerEl => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();
                        println!("Instruction Abort (Lower EL) at {:#x}", pc);

                        // Send SIGSEGV signal to GDB to indicate fault
                        if let Some(ref sender) = notification_sender {
                            appbox::gdb::send_sigsegv(sender);
                        }

                        // Enter GDB evaluation loop for system state inspection
                        loop {
                            if let Ok(cmd) = command_receiver.recv() {
                                match cmd {
                                    appbox::gdb::GdbCommand::Continue => break,
                                    appbox::gdb::GdbCommand::Kill => return,
                                    appbox::gdb::GdbCommand::BackwardsStep => {
                                        // Reset VM to initial state
                                        vm.vcpu.set_reg(av::Reg::PC, initial_pc).unwrap();
                                        vm.vcpu
                                            .set_sys_reg(av::SysReg::SP_EL0, initial_sp)
                                            .unwrap();

                                        // Reset warpspeed to beginning of trace
                                        warpspeed = warpspeed::Warpspeed::new(
                                            trace.clone(),
                                            warpspeed::Mode::Replay,
                                        );

                                        // Remove any existing single step breakpoint
                                        if let Some(addr) = single_step_breakpoint.take() {
                                            let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                                        }

                                        // Set breakpoint at PC - 4 (previous instruction)
                                        if initial_pc >= 4 {
                                            let prev_pc = initial_pc - 4;
                                            vm.hooks.add_breakpoint(prev_pc, &mut vm.vma).unwrap();
                                            single_step_breakpoint = Some(prev_pc);
                                        }
                                        break;
                                    }
                                    appbox::gdb::GdbCommand::BackwardsContinue => {
                                        // Reset VM to initial state
                                        vm.vcpu.set_reg(av::Reg::PC, initial_pc).unwrap();
                                        vm.vcpu
                                            .set_sys_reg(av::SysReg::SP_EL0, initial_sp)
                                            .unwrap();

                                        // Reset warpspeed to beginning of trace
                                        warpspeed = warpspeed::Warpspeed::new(
                                            trace.clone(),
                                            warpspeed::Mode::Replay,
                                        );

                                        // Remove any existing single step breakpoint
                                        if let Some(addr) = single_step_breakpoint.take() {
                                            let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                                        }
                                        break;
                                    }
                                    _ => handle_gdb_command(cmd, &mut vm, &response_sender),
                                }
                            }
                        }

                        // Always crash after inspection - no recovery possible
                        ExitKind::Crash("Instruction Abort".to_string())
                    }
                    _ => Err(ExceptionError::UnimplementedException(
                        exit_info.exception.syndrome,
                    ))
                    .unwrap(),
                }
            }
            av::ExitReason::CANCELED => ExitKind::Timeout,
            av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
            av::ExitReason::UNKNOWN => panic!(
                "Vcpu exited unexpectedly at address {:#x}",
                vm.vcpu.get_reg(av::Reg::PC).unwrap()
            ),
        };

        match exit {
            ExitKind::Continue => continue,
            _ => break,
        };
    }
}
