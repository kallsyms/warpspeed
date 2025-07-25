use appbox::applevisor as av;
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::vm::VmManager;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::cli;
use crate::recordable;
use crate::warpspeed;

use recordable::{trace::Target, Trace};

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

    loop {
        vm.vcpu.run().unwrap();

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
                        println!("Breakpoint hit at {:#x}", pc);
                        vm.hooks.handle(&mut vm.vcpu, &mut vm.vma).unwrap();
                        ExitKind::Continue
                    }
                    ExceptionClass::InsAbortLowerEl => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap();
                        println!("Instruction Abort (Lower EL) at {:#x}", pc);
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
