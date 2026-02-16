use anyhow::Result;
use appbox::applevisor as av;
use appbox::gdb::{GdbCommand, GdbResponse};
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::vm::{VmManager, VmRunResult};
use log::{debug, error, info, trace};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::cli;
use crate::recordable;
use crate::warpspeed;

use recordable::{trace::Target, Trace};

fn handle_gdb_command(
    cmd: GdbCommand,
    vm: &mut VmManager,
    response_sender: &std::sync::mpsc::Sender<GdbResponse>,
) {
    appbox::gdb::handle_command(cmd, vm, response_sender)
}

pub fn record(args: &cli::RecordArgs) -> Result<()> {
    let mut argv = vec![args.executable.clone()];
    argv.extend_from_slice(&args.arguments);
    let env = vec![]; // TODO

    let target = Target {
        path: args.executable.clone(),
        arguments: argv.clone(),
        environment: env.clone(),
    };

    let mut warpspeed = warpspeed::Warpspeed::new(
        Trace {
            target: Some(target),
            events: vec![],
        },
        warpspeed::Mode::Record,
    );

    let mut vm = VmManager::new()?;

    let loader =
        appbox::loader::load_macho(&mut vm, &PathBuf::from(args.executable.clone()), argv, env)?;

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;

    // GDB server channels
    let (command_sender, command_receiver) = std::sync::mpsc::channel();
    let (response_sender, response_receiver) = std::sync::mpsc::channel();

    let notification_sender = if let Some(port) = args.gdb_port {
        Some(appbox::gdb::start_gdb_server(
            port,
            command_sender,
            response_receiver,
            None,
            appbox::gdb::GdbFeatures::default(),
        )?)
    } else {
        None
    };

    let mut single_step_breakpoint: Option<u64> = None;

    if args.gdb_port.is_some() {
        if args.gdb_wait {
            info!("Waiting for GDB connection...");
            loop {
                if let Ok(cmd) = command_receiver.recv() {
                    match cmd {
                        appbox::gdb::GdbCommand::Continue => break,
                        appbox::gdb::GdbCommand::Step => {
                            // Get current instruction to determine next PC
                            let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                            let mut insn_bytes = [0; 4];
                            vm.vma.read(pc, &mut insn_bytes)?;

                            // For now, assume next instruction is at PC + 4
                            // TODO: Enhance this to handle branches properly by using instruction emulation
                            let next_pc = pc + 4;

                            // Set new single step breakpoint
                            vm.hooks.add_breakpoint(next_pc, &mut vm.vma)?;
                            single_step_breakpoint = Some(next_pc);
                            break;
                        }
                        appbox::gdb::GdbCommand::Kill => {
                            return Ok(());
                        }
                        _ => handle_gdb_command(cmd, &mut vm, &response_sender),
                    }
                }
            }
        }
    }

    loop {
        trace!("Running VCPU");
        let run_result = vm.run()?;
        trace!("VCPU exit");

        // while let Ok(cmd) = command_receiver.try_recv() {
        //     match cmd {
        //         appbox::gdb::GdbCommand::Continue => {
        //             // Remove single step breakpoint if it exists
        //             if let Some(addr) = single_step_breakpoint.take() {
        //                 let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
        //             }
        //             break;
        //         }

        //         appbox::gdb::GdbCommand::Step => {
        //             // Get current instruction to determine next PC
        //             let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();
        //             let mut insn_bytes = [0; 4];
        //             vm.vma.read(pc, &mut insn_bytes).unwrap();

        //             // Remove previous single step breakpoint if it exists
        //             if let Some(addr) = single_step_breakpoint.take() {
        //                 let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
        //             }

        //             // For now, assume next instruction is at PC + 4
        //             // TODO: Enhance this to handle branches properly by using instruction emulation
        //             let next_pc = pc + 4;

        //             // Set new single step breakpoint
        //             vm.hooks.add_breakpoint(next_pc, &mut vm.vma).unwrap();
        //             single_step_breakpoint = Some(next_pc);
        //             break;
        //         }

        //         appbox::gdb::GdbCommand::Kill => {
        //             return;
        //         }

        //         _ => {
        //             handle_gdb_command(cmd, &mut vm, &response_sender);
        //         }
        //     }
        // }

        let exit = match run_result {
            VmRunResult::Svc => {
                let exit = warpspeed.trap_handler(&mut vm.vcpu, &mut vm.vma, &loader)?;

                if let ExitKind::Crash(_) = exit {
                    // Send SIGSEGV signal to GDB to indicate fault
                    if let Some(ref sender) = notification_sender {
                        appbox::gdb::send_sigsegv(sender);
                    }

                    // Enter GDB evaluation loop for system state inspection
                    loop {
                        if let Ok(cmd) = command_receiver.recv() {
                            match cmd {
                                appbox::gdb::GdbCommand::Continue => break,
                                appbox::gdb::GdbCommand::Step => break,
                                appbox::gdb::GdbCommand::Kill => return Ok(()),
                                _ => appbox::gdb::handle_command(cmd, &mut vm, &response_sender),
                            }
                        }
                    }
                }

                exit
            }
            VmRunResult::Brk => {
                let pc = vm.vcpu.get_reg(av::Reg::PC)?;

                // Check if this is our single step breakpoint
                if Some(pc) == single_step_breakpoint {
                    debug!("Single step completed at {:#x}", pc);
                    vm.hooks.prepare_for_debugger(&mut vm.vcpu, &mut vm.vma)?;
                    // Remove the single step breakpoint
                    vm.hooks.remove_breakpoint(pc, &mut vm.vma)?;
                    single_step_breakpoint = None;
                    if let Some(ref sender) = notification_sender {
                        sender.send(appbox::gdb::GdbNotification::Stop(
                            5, // SIGTRAP
                        ))?;
                    }
                    // Enter GDB evaluation loop for system state inspection
                    loop {
                        if let Ok(cmd) = command_receiver.recv() {
                            match cmd {
                                appbox::gdb::GdbCommand::Continue => break,
                                appbox::gdb::GdbCommand::Step => {
                                    let next_pc =
                                        vm.hooks.compute_step_target(&vm.vcpu, &vm.vma)?;
                                    vm.hooks.add_breakpoint(next_pc, &mut vm.vma)?;
                                    single_step_breakpoint = Some(next_pc);
                                    break;
                                }
                                appbox::gdb::GdbCommand::Kill => return Ok(()),
                                _ => appbox::gdb::handle_command(cmd, &mut vm, &response_sender),
                            }
                        }
                    }
                    appbox::hyperpom::caches::Caches::ic_ivau(&mut vm.vcpu, &mut vm.vma)?;
                    ExitKind::Continue
                } else {
                    debug!("Breakpoint hit at {:#x}", pc);
                    // Restore original instruction
                    vm.hooks.prepare_for_debugger(&mut vm.vcpu, &mut vm.vma)?;
                    if let Some(ref sender) = notification_sender {
                        sender.send(appbox::gdb::GdbNotification::Stop(
                            5, // SIGTRAP
                        ))?;
                    }
                    // Enter GDB evaluation loop for system state inspection
                    loop {
                        if let Ok(cmd) = command_receiver.recv() {
                            match cmd {
                                appbox::gdb::GdbCommand::Continue => break,
                                appbox::gdb::GdbCommand::Step => {
                                    let next_pc =
                                        vm.hooks.compute_step_target(&vm.vcpu, &vm.vma)?;
                                    vm.hooks.add_breakpoint(next_pc, &mut vm.vma)?;
                                    single_step_breakpoint = Some(next_pc);
                                    break;
                                }
                                appbox::gdb::GdbCommand::Kill => return Ok(()),
                                _ => appbox::gdb::handle_command(cmd, &mut vm, &response_sender),
                            }
                        }
                    }
                    appbox::hyperpom::caches::Caches::ic_ivau(&mut vm.vcpu, &mut vm.vma)?;
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
                            if let Some(ref sender) = notification_sender {
                                appbox::gdb::send_sigsegv(sender);
                            }

                            // Enter GDB evaluation loop for system state inspection
                            loop {
                                if let Ok(cmd) = command_receiver.recv() {
                                    match cmd {
                                        appbox::gdb::GdbCommand::Continue => break,
                                        appbox::gdb::GdbCommand::Step => break,
                                        _ => appbox::gdb::handle_command(
                                            cmd,
                                            &mut vm,
                                            &response_sender,
                                        ),
                                    }
                                }
                            }

                            // Always crash after inspection - no recovery possible
                            ExitKind::Crash("Instruction Abort".to_string())
                        }
                        _ => {
                            error!(
                                "Unimplemented exception class {:?} (syndrome=0x{:x})",
                                ExceptionClass::from(exit_info.exception.syndrome >> 26),
                                exit_info.exception.syndrome
                            );
                            let elr = vm.vcpu.get_sys_reg(av::SysReg::ELR_EL1).unwrap_or(0);
                            if elr != 0 {
                                let mut insn = [0u8; 4];
                                if vm.vma.read(elr, &mut insn).is_ok() {
                                    let word = u32::from_le_bytes(insn);
                                    error!("ELR_EL1: 0x{:016x} insn=0x{:08x}", elr, word);
                                } else {
                                    error!("ELR_EL1: 0x{:016x} (read failed)", elr);
                                }
                            }
                            error!("{}", appbox::format_vm_state(&vm));
                            error!("== User Stack ==");
                            let frames = appbox::unwind_user_stack(&vm, 64);
                            let vbar = vm.vcpu.get_sys_reg(av::SysReg::VBAR_EL1).unwrap_or(0);
                            for (idx, addr) in frames.iter().enumerate() {
                                if vbar != 0 && *addr >= vbar && *addr < vbar + 0x1000 {
                                    error!("{:02} 0x{:016x} (exception vector)", idx, addr);
                                    continue;
                                }
                                if let Some(sym) = loader.symbolicate(*addr) {
                                    let offset = addr.saturating_sub(sym.symbol_addr);
                                    error!(
                                        "{:02} 0x{:016x} {}::{} + 0x{:x}",
                                        idx, addr, sym.image, sym.symbol, offset
                                    );
                                } else {
                                    error!("{:02} 0x{:016x}", idx, addr);
                                }
                            }
                            return Err(ExceptionError::UnimplementedException(
                                exit_info.exception.syndrome,
                            )
                            .into());
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
            _ => break,
        };
    }

    let mut output = File::create(&args.trace_filename)?;
    output.write_all(prost::Message::encode_to_vec(&warpspeed.trace).as_slice())?;

    Ok(())
}
