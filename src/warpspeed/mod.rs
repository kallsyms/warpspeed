use anyhow::Result;
use appbox::hyperpom::memory::VirtMemAllocator;
use appbox::loader::Loader;
use log::{debug, error, trace};
use std::collections::HashMap;

use appbox::applevisor as av;
use appbox::hyperpom::crash::ExitKind;
use appbox::syscalls;
use appbox::trap::{
    explore_pointers, read_syscall_context, write_syscall_result, DefaultTrapHandler,
    SyscallResult, TrapHandler,
};

use crate::recordable;
use crate::recordable::side_effects;

fn diff_memory(page_addr: u64, old: &[u8], new: &[u8]) -> Vec<side_effects::Memory> {
    let mut side_effects = vec![];

    assert!(old.len() == new.len());

    let mut start = None;
    for (i, (a, b)) in old.iter().zip(new.iter()).enumerate() {
        if a != b {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            side_effects.push(side_effects::Memory {
                address: page_addr + s as u64,
                value: new[start.unwrap()..i].to_vec(),
            });
            start = None;
        }
    }

    if let Some(s) = start {
        side_effects.push(side_effects::Memory {
            address: page_addr + s as u64,
            value: new[s..].to_vec(),
        });
    }

    side_effects
}

#[derive(PartialEq)]
pub enum Mode {
    Record,
    Replay,
}

pub struct Warpspeed {
    pub trace: recordable::Trace,
    mode: Mode,
    event_idx: usize,

    tsd: u64,
    trap_handler: DefaultTrapHandler,
}

impl Warpspeed {
    pub fn new(trace: recordable::Trace, mode: Mode) -> Self {
        Self {
            trace,
            mode,
            event_idx: 0,
            tsd: 0,
            trap_handler: DefaultTrapHandler::new(),
        }
    }

    pub fn trap_handler(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        loader: &Loader,
    ) -> Result<ExitKind> {
        let ctx = read_syscall_context(vcpu)?;
        let elr = ctx.elr;
        trace!("ELR_EL1: {:#x}", elr);
        if ctx.esr != 0x56000080 {
            error!("Fault!");
            error!("{}", vcpu);
            return Ok(ExitKind::Crash("Unhandled fault".to_string()));
        }

        let num = ctx.num;
        let args = ctx.args;
        debug!(
            "{}: Incoming syscall ({}) {:x}(x{:x?})",
            self.event_idx,
            syscalls::syscall_name(num).unwrap_or("<unknown>"),
            num,
            args
        );

        let mut ret0: u64 = 0;
        let mut ret1: u64 = 0;
        let mut cflags: u64 = 0;
        let mut side_effects = recordable::SideEffects::default();
        if num == 0x8000_0000 {
            let code = args[3];
            if code == 2 {
                self.tsd = args[0];
            }
        }

        // Stage 2: do the syscall.
        // If recording:
        //   1. Snapshot "reachable" memory before the syscall
        //   2. Perform the syscall
        //   3. Diff previously stored reachable pages now that the syscall is done, recording what memory changed.
        // If replaying, make sure we're in the correct place and simply apply the side effects.
        match self.mode {
            Mode::Record => {
                let mut before_pages = HashMap::new();
                for page_addr in explore_pointers(vma, &args) {
                    let mut contents: Vec<u8> = vec![0; 0x1000];
                    vma.read(page_addr, &mut contents)?;
                    before_pages.insert(page_addr, contents);
                }

                let res = self.trap_handler.handle_syscall(&ctx, vcpu, vma, loader)?;
                if res.exit != ExitKind::Continue {
                    return Ok(res.exit);
                }
                ret0 = res.ret0;
                ret1 = res.ret1;
                cflags = res.cflags;

                match num {
                    syscalls::SYS_read
                    | syscalls::SYS_pread
                    | syscalls::SYS_read_nocancel
                    | syscalls::SYS_pread_nocancel => {
                        let buf = args[1];
                        let count = ret0;
                        let mut data = vec![0; count as usize];
                        vma.read(buf, &mut data)?;
                        side_effects.memory.push(recordable::side_effects::Memory {
                            address: buf,
                            value: data,
                        });
                    }
                    _ => {
                        for (page_addr, old_contents) in before_pages {
                            let mut new_contents: Vec<u8> = vec![0; 0x1000];
                            vma.read(page_addr, &mut new_contents)?;
                            side_effects.memory.extend(diff_memory(
                                page_addr,
                                &old_contents,
                                &new_contents,
                            ));
                        }
                    }
                }

                trace!(
                    "Changed mem: {:?}",
                    side_effects
                        .memory
                        .iter()
                        .map(|m| (m.address, m.address + m.value.len() as u64))
                        .collect::<Vec<_>>()
                );
            }
            Mode::Replay => {
                let event = &self.trace.events[self.event_idx];
                if elr != event.pc {
                    error!(
                        "Replay {}: pc mismatch: expected 0x{:x}, got 0x{:x}",
                        self.event_idx, event.pc, elr
                    );
                    return Ok(ExitKind::Exit);
                }

                match &event.event {
                    Some(crate::recordable::log_event::Event::Syscall(syscall)) => {
                        if num != syscall.syscall_number {
                            error!(
                                "Replay {}: syscall mismatch: expected 0x{:x}, got 0x{:x}",
                                self.event_idx, syscall.syscall_number, num
                            );
                        }

                        let side_effects_ref = syscall.side_effects.as_ref().unwrap();
                        let should_call = side_effects_ref.external || num == 0x8000_0000;
                        let mut res: Option<SyscallResult> = None;

                        if should_call {
                            trace!("Replay syscall index {}", self.event_idx);
                            let handler_res =
                                self.trap_handler.handle_syscall(&ctx, vcpu, vma, loader)?;
                            if handler_res.exit != ExitKind::Continue {
                                return Ok(handler_res.exit);
                            }
                            res = Some(handler_res);
                        }

                        for reg in &side_effects_ref.registers {
                            trace!("Setting X{:?} to 0x{:x}", reg.register, reg.value);
                            match reg.register {
                                0x0 => {
                                    if side_effects_ref.external {
                                        if let Some(handler_res) = &res {
                                            if handler_res.ret0 != reg.value {
                                                error!(
                                                    "Replay {}: syscall return value 0 mismatch: expected 0x{:x}, got 0x{:x}",
                                                    self.event_idx, reg.value, handler_res.ret0
                                                );
                                            }
                                        }
                                    }
                                    ret0 = reg.value
                                }
                                0x1 => {
                                    if side_effects_ref.external {
                                        if let Some(handler_res) = &res {
                                            if handler_res.ret1 != reg.value {
                                                error!(
                                                    "Replay {}: syscall return value 1 mismatch: expected 0x{:x}, got 0x{:x}",
                                                    self.event_idx, reg.value, handler_res.ret1
                                                );
                                            }
                                        }
                                    }
                                    ret1 = reg.value
                                }
                                0x22 => cflags = reg.value,
                                _ => {
                                    error!(
                                        "Replay {}: unexpected register: {:?}",
                                        self.event_idx, reg.register
                                    );
                                    return Ok(ExitKind::Exit);
                                }
                            }
                        }
                        for mem in &side_effects_ref.memory {
                            trace!("Writing to 0x{:x}", mem.address);
                            unsafe {
                                std::ptr::copy(
                                    mem.value.as_ptr(),
                                    mem.address as _,
                                    mem.value.len(),
                                );
                            }
                        }
                    }
                    _ => {
                        error!(
                            "replay {}: unexpected event type: {:?}",
                            self.event_idx, event.event
                        );
                        return Ok(ExitKind::Exit);
                    }
                }
            }
        }

        // Stage 3: now that we've done the syscall, record the final state as side effects.
        let cpsr = (vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | cflags;

        if self.mode == Mode::Record {
            side_effects.registers.extend(vec![
                recordable::side_effects::Register {
                    register: av::Reg::X0 as _,
                    value: ret0,
                },
                recordable::side_effects::Register {
                    register: av::Reg::X1 as _,
                    value: ret1,
                },
                recordable::side_effects::Register {
                    register: av::Reg::CPSR as _,
                    value: cpsr,
                },
            ]);

            // These syscalls have external side-effects, so the syscall itself must be run on replay.
            // mmap, mach_vm_allocate, and mach_vm_map already set this above.
            // TODO: open/close and other fd manipulating calls are needed so mmapping fds works,
            // but these shouldn't be needed eventually.
            if num == syscalls::SYS_open
                || num == syscalls::SYS_openat
                || num == syscalls::SYS_open_nocancel
                || num == syscalls::SYS_openat_nocancel
                || num == syscalls::SYS_close
                || num == syscalls::SYS_close_nocancel
                || num == syscalls::SYS_dup
                || num == syscalls::SYS_dup2
                // and socket is needed so the fd table stays in sync
                || num == syscalls::SYS_socket
            {
                side_effects.external = true;
            }

            // Also include write_nocancel so we can see stdout/stderr.
            if num == syscalls::SYS_write_nocancel && (args[0] == 1 || args[0] == 2) {
                side_effects.external = true;
            }

            if num == syscalls::SYS_mmap
                || num == syscalls::TRAP_mach_vm_allocate
                || num == syscalls::TRAP_mach_vm_map
            {
                side_effects.external = true;
            }
            if num == syscalls::TRAP_mach_msg2 {
                let msgh_id = args[4] >> 32;
                if msgh_id == 4811 {
                    side_effects.external = true;
                }
            }

            self.trace.events.push(recordable::LogEvent {
                pc: elr,
                register_state: args.to_vec(),
                event: Some(recordable::log_event::Event::Syscall(
                    recordable::syscall::Syscall {
                        syscall_number: num as _,
                        side_effects: Some(side_effects),
                    },
                )),
            });
        }

        self.event_idx += 1;

        debug!("Returning x0={:x} x1={:x} cpsr={:x}", ret0, ret1, cpsr);
        write_syscall_result(vcpu, elr, ret0, ret1, cflags)?;
        vcpu.set_sys_reg(av::SysReg::TPIDRRO_EL0, self.tsd)?;

        Ok(ExitKind::Continue)
    }
}
