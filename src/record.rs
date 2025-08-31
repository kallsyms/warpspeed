use appbox::applevisor as av;
use appbox::gdb::{GdbCommand, GdbResponse};
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::vm::VmManager;
use log::{debug, info, trace};
use prost::Message;
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

pub fn record(args: &cli::RecordArgs) {
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

    let mut vm = VmManager::new().unwrap();

    let loader =
        appbox::loader::load_macho(&mut vm, &PathBuf::from(args.executable.clone()), argv, env)
            .unwrap();

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point).unwrap();
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)
        .unwrap();

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
                appbox::gdb::GdbFeatures::default(),
            )
            .unwrap(),
        )
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
                            let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();
                            let mut insn_bytes = [0; 4];
                            vm.vma.read(pc, &mut insn_bytes).unwrap();

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
                        _ => handle_gdb_command(cmd, &mut vm, &response_sender),
                    }
                }
            }
        }
    }

    loop {
        trace!("Running VCPU");
        vm.vcpu.run().unwrap();
        trace!("VCPU exit");

        let exit_info = vm.vcpu.get_exit_info();
        let esr = vm.vcpu.get_sys_reg(av::SysReg::ESR_EL1).unwrap();
        if exit_info.exception.syndrome & 0xf == 8  // Synchronous Exception from Lower EL using AArch64
            && ExceptionClass::from(esr >> 26) == ExceptionClass::DataAbortLowerEl
        {
            let far = vm.vcpu.get_sys_reg(av::SysReg::FAR_EL1).unwrap();
            if vm.vma.page_fault_dirty_state_handler(far) == Ok(true) {
                trace!("Handled write page fault at {:#x}", far);
                // Retry the instruction that caused the page fault
                let elr = vm.vcpu.get_sys_reg(av::SysReg::ELR_EL1).unwrap();
                vm.vcpu.set_reg(av::Reg::PC, elr).unwrap();
                appbox::hyperpom::caches::Caches::tlbi_vaae1_on_fault(&mut vm.vcpu, &mut vm.vma)
                    .unwrap();
                continue;
            }
        }

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

                _ => {
                    handle_gdb_command(cmd, &mut vm, &response_sender);
                }
            }
        }

        // https://github.com/kallsyms/hyperpom/blob/a1dd1aebd8f306bb8549595d9d1506c2a361f0d7/src/core.rs#L1535
        let exit = match exit_info.reason {
            av::ExitReason::EXCEPTION => {
                match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                    ExceptionClass::HvcA64 => {
                        let exit = warpspeed
                            .trap_handler(&mut vm.vcpu, &mut vm.vma, &loader)
                            .unwrap();

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
                                        appbox::gdb::GdbCommand::Kill => return,
                                        _ => appbox::gdb::handle_command(
                                            cmd,
                                            &mut vm,
                                            &response_sender,
                                        ),
                                    }
                                }
                            }
                        }

                        exit
                    }
                    ExceptionClass::BrkA64 => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();

                        // Check if this is our single step breakpoint
                        if Some(pc) == single_step_breakpoint {
                            println!("Single step completed at {:#x}", pc);
                            // Remove the single step breakpoint
                            vm.hooks.remove_breakpoint(pc, &mut vm.vma).unwrap();
                            single_step_breakpoint = None;
                            if let Some(ref sender) = notification_sender {
                                appbox::gdb::send_sigsegv(sender);
                            }
                            // Enter GDB evaluation loop for system state inspection
                            loop {
                                if let Ok(cmd) = command_receiver.recv() {
                                    match cmd {
                                        appbox::gdb::GdbCommand::Continue => break,
                                        appbox::gdb::GdbCommand::Kill => return,
                                        _ => appbox::gdb::handle_command(
                                            cmd,
                                            &mut vm,
                                            &response_sender,
                                        ),
                                    }
                                }
                            }
                            ExitKind::Continue
                        } else {
                            println!("Breakpoint hit at {:#x}", pc);
                            // TODO: restore insn before gdb eval. needs to be broken out from hooks otherwise vm state is pointing to the ic_ivau handler
                            // TODO: only trigger gdb on bp stage 1
                            if let Some(ref sender) = notification_sender {
                                appbox::gdb::send_sigsegv(sender);
                            }
                            // Enter GDB evaluation loop for system state inspection
                            loop {
                                if let Ok(cmd) = command_receiver.recv() {
                                    match cmd {
                                        appbox::gdb::GdbCommand::Continue => break,
                                        appbox::gdb::GdbCommand::Kill => return,
                                        _ => appbox::gdb::handle_command(
                                            cmd,
                                            &mut vm,
                                            &response_sender,
                                        ),
                                    }
                                }
                            }
                            vm.hooks.handle(&mut vm.vcpu, &mut vm.vma).unwrap();
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
                                    _ => {
                                        appbox::gdb::handle_command(cmd, &mut vm, &response_sender)
                                    }
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

    let mut output = File::create(&args.trace_filename).unwrap();
    output
        .write_all(prost::Message::encode_to_vec(&warpspeed.trace).as_slice())
        .unwrap();
}
