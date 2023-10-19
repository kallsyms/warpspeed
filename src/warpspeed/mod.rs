use log::{debug, error, info, trace, warn};
use std::arch::asm;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::ffi::CStr;

use hyperpom::applevisor as av;
use hyperpom::crash::*;
use hyperpom::error::*;
use hyperpom::memory::*;

use appbox::{AppBoxTrapHandler, LoadInfo};

use crate::recordable;

// https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/kern_return.h#L325
const KERN_DENIED: u64 = 53;
const KERN_NOT_FOUND: u64 = 56;

// explore from the given set of potential pointers, returning a set of pages that are
// accessible from the set of pointers.
fn explore_pointers(vma: &mut VirtMemAllocator, entry_points: &[u64]) -> HashSet<u64> {
    let mut queue = entry_points
        .iter()
        .filter_map(|&addr| {
            if vma.read_byte(addr).is_ok() {
                Some((addr, 0))
            } else {
                None
            }
        })
        .collect::<VecDeque<_>>();
    let mut pages = HashSet::from_iter(queue.iter().map(|&(addr, _)| addr & !0xfff));

    while let Some((start_addr, depth)) = queue.pop_front() {
        let mut last_page = start_addr & !0xfff;
        for addr in start_addr..start_addr + 0x200 {
            // +0x200 can take us to a new, potentially unmapped page so we have to check.
            // But we only have to do this when crossing the page boundry, not every time.
            if (addr + 8) & !0xfff != last_page {
                if !vma.read_byte(addr + 8).is_ok() {
                    break;
                } else {
                    last_page = (addr + 8) & !0xfff;
                }
            }
            let value = vma.read_qword(addr).unwrap();
            if !vma.read_byte(value).is_ok() {
                continue;
            }
            let page_addr = value & !0xfff;
            if !pages.contains(&page_addr) {
                pages.insert(page_addr);
                if depth < 2 {
                    queue.push_back((value, depth + 1));
                }
            }
        }
    }

    pages
}

#[derive(Clone)]
pub enum Mode {
    Record,
    Replay,
}

#[derive(Clone)]
pub struct Warpspeed {
    pub trace: recordable::Trace,
    mode: Mode,
    event_idx: usize,

    mappings: Vec<(u64, usize)>,
}

impl Warpspeed {
    pub fn new(trace: recordable::Trace, mode: Mode) -> Self {
        Self {
            trace,
            mode,
            event_idx: 0,
            mappings: vec![],
        }
    }
}

impl AppBoxTrapHandler for Warpspeed {
    fn trap_handler(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        load_info: &LoadInfo,
    ) -> Result<ExitKind> {
        let elr = vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
        trace!("ELR_EL1: {:#x}", elr);
        let esr = vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;

        if esr != 0x56000080 {
            error!("Fault!");
            error!("{}", vcpu);
            return Ok(ExitKind::Crash("Unhandled fault".to_string()));
        }

        // This is our syscall handler
        let num = vcpu.get_reg(av::Reg::X16)?;
        let mut args: [u64; 16] = [
            vcpu.get_reg(av::Reg::X0)?,
            vcpu.get_reg(av::Reg::X1)?,
            vcpu.get_reg(av::Reg::X2)?,
            vcpu.get_reg(av::Reg::X3)?,
            vcpu.get_reg(av::Reg::X4)?,
            vcpu.get_reg(av::Reg::X5)?,
            vcpu.get_reg(av::Reg::X6)?,
            vcpu.get_reg(av::Reg::X7)?,
            vcpu.get_reg(av::Reg::X8)?,
            vcpu.get_reg(av::Reg::X9)?,
            vcpu.get_reg(av::Reg::X10)?,
            vcpu.get_reg(av::Reg::X11)?,
            vcpu.get_reg(av::Reg::X12)?,
            vcpu.get_reg(av::Reg::X13)?,
            vcpu.get_reg(av::Reg::X14)?,
            vcpu.get_reg(av::Reg::X15)?,
        ];
        debug!("Incoming syscall {:x}(0x{:x?})", num, args);

        let mut ret0: u64 = 0;
        let mut ret1: u64 = 0;
        let mut cflags: u64 = 0;
        let mut changed_pages = HashMap::new();
        let mut side_effects = vec![];

        let mut handled = false;
        match num {
            0x1 => {
                // exit
                // TODO: log trace
                return Ok(ExitKind::Exit);
            }
            0x5 => {
                // open
                debug!("open({})", unsafe {
                    CStr::from_ptr(args[0] as _).to_string_lossy()
                });
            }
            0x49 => {
                // munmap
                if let Some(mapping_idx) = self
                    .mappings
                    .iter()
                    .position(|&(va, len)| va == args[0] && len as u64 == args[1])
                {
                    trace!("munmap({:x}, {:x})", args[0], args[1]);
                    self.mappings.remove(mapping_idx);
                }
                handled = true;
            }
            0x4a => {
                // mprotect
                handled = true;
            }
            0xfffffffffffffff2 => {
                // mach_vm_protect
                handled = true;
            }
            0xfffffffffffffff4 => {
                // mach_vm_deallocate
                handled = true;
                // TODO: remove from mappings
            }
            0x10a => {
                // shm_open
                let name = unsafe { CStr::from_ptr(args[0] as _) };
                trace!("shm_open({})", name.to_string_lossy());
                if name.to_string_lossy() == "com.apple.featureflags.shm" {
                    debug!("Denying shm_open for featureflag");
                    ret0 = KERN_DENIED;
                    ret1 = 0;
                    cflags = 1 << 29;
                    handled = true;
                }
            }
            0x126 => {
                // shared_region_check_np
                // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/vm/vm_unix.c#L2017
                if args[0] != u64::MAX {
                    debug!(
                        "Returning {:x} for shared_region_check_np",
                        load_info.shared_cache_base
                    );
                    // *(uint64_t*)args[0] = shared_cache_base
                    unsafe {
                        *(args[0] as *mut u64) = load_info.shared_cache_base;
                    }
                }
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            0x150 => {
                // proc_info
                if args[0] == 0xf {
                    debug!("Stubbing out proc_info for PROC_INFO_CALL_SET_DYLD_IMAGES");
                    ret0 = 0;
                    ret1 = 0;
                    cflags = 0;
                    handled = true;
                }
            }
            0xffffffffffffffd1 => {
                // mach_msg2
                let flavor: u32 = unsafe { *((args[0] + 0x20) as *const u32) };
                // TODO: actually check for this being task_info
                if flavor == 0x11 {
                    debug!("Returning NOT_FOUND for TASK_DYLD_INFO");
                    ret0 = KERN_NOT_FOUND;
                    ret1 = 0;
                    cflags = 1 << 29;
                    handled = true;
                }
            }
            _ => {}
        }

        if !handled {
            match self.mode {
                Mode::Record => {
                    // map of addr -> page contents
                    let mut before_pages = HashMap::new();
                    for page_addr in explore_pointers(vma, &args) {
                        let mut contents: Vec<u8> = vec![0; 0x1000];
                        vma.read(page_addr, &mut contents)?;
                        before_pages.insert(page_addr, contents);
                    }

                    debug!(
                        "{}: Forwarding syscall {:x}(0x{:x?})",
                        self.trace.events.len(),
                        num,
                        args
                    );
                    unsafe {
                        asm!(
                            "svc #0x80",
                            "mov {ret0}, x0",
                            "mov {ret1}, x1",
                            "mrs {cflags}, NZCV",
                            in("x0") args[0],
                            in("x1") args[1],
                            in("x2") args[2],
                            in("x3") args[3],
                            in("x4") args[4],
                            in("x5") args[5],
                            in("x6") args[6],
                            in("x7") args[7],
                            in("x8") args[8],
                            in("x9") args[9],
                            in("x10") args[10],
                            in("x11") args[11],
                            in("x12") args[12],
                            in("x13") args[13],
                            in("x14") args[14],
                            in("x15") args[15],
                            in("x16") num,
                            ret0 = out(reg) ret0,
                            ret1 = out(reg) ret1,
                            cflags = out(reg) cflags,
                        );
                    }

                    if num == 3 || num == 396 {
                        for (page_addr, old_contents) in before_pages {
                            let mut new_contents: Vec<u8> = vec![0; 0x1000];
                            vma.read(page_addr, &mut new_contents)?;
                            for i in 0..0x1000 {
                                if old_contents[i] != new_contents[i] {
                                    changed_pages
                                        .insert(page_addr + i as u64, vec![new_contents[i]]);
                                }
                            }
                        }
                    }

                    trace!("Changed pages: {:?}", changed_pages.keys());
                }

                Mode::Replay => {
                    let event = &self.trace.events[self.event_idx];
                    if elr != event.pc {
                        if num == 4 {
                            trace!("msg: {:x?}", unsafe { CStr::from_ptr(args[1] as _) });
                            vcpu.set_reg(av::Reg::X0, args[2])?;
                            vcpu.set_reg(av::Reg::X1, 0)?;
                            vcpu.set_reg(
                                av::Reg::CPSR,
                                vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28),
                            )?;
                            vcpu.set_reg(av::Reg::PC, elr)?;
                            return Ok(ExitKind::Continue);
                        }
                        error!(
                            "replay {}: pc mismatch: expected 0x{:x}, got 0x{:x}",
                            self.event_idx, event.pc, elr
                        );
                        return Ok(ExitKind::Exit);
                    }

                    match &event.event {
                        Some(crate::recordable::log_event::Event::Syscall(syscall)) => {
                            if num != syscall.syscall_number {
                                error!(
                                    "replay {}: syscall mismatch: expected 0x{:x}, got 0x{:x}",
                                    self.event_idx, syscall.syscall_number, num
                                );
                            }
                            for side_effect in &syscall.side_effects {
                                match &side_effect.kind {
                                    Some(crate::recordable::side_effect::Kind::Register(reg)) => {
                                        trace!(
                                            "replay {}: setting {:?} to 0x{:x}",
                                            self.event_idx,
                                            reg.register,
                                            reg.value
                                        );
                                        match reg.register {
                                            0x0 => ret0 = reg.value,
                                            0x1 => ret1 = reg.value,
                                            0x22 => cflags = reg.value,
                                            _ => {
                                                error!(
                                                    "replay {}: unexpected register: {:?}",
                                                    self.event_idx, reg.register
                                                );
                                                return Ok(ExitKind::Exit);
                                            }
                                        }
                                    }
                                    Some(crate::recordable::side_effect::Kind::Memory(mem)) => {
                                        trace!(
                                            "replay {}: writing to 0x{:x}",
                                            self.event_idx,
                                            mem.address
                                        );
                                        unsafe {
                                            std::ptr::copy(
                                                mem.value.as_ptr(),
                                                mem.address as _,
                                                mem.value.len(),
                                            );
                                        }
                                    }
                                    Some(crate::recordable::side_effect::Kind::External(ext)) => {
                                        match num {
                                            0xc5 => {
                                                args[0] = ext.address;
                                                args[2] = (nix::libc::PROT_READ
                                                    | nix::libc::PROT_WRITE)
                                                    as u64;
                                                args[3] = nix::libc::MAP_FIXED as u64
                                                    | nix::libc::MAP_ANONYMOUS as u64;
                                                args[4] = -1 as i64 as u64;
                                                // contents will be updated by subsequent memory sideeffect
                                            }
                                            0xfffffffffffffff6 => unsafe {
                                                *(args[1] as *mut u64) = ext.address;
                                                args[3] &= !0x1;
                                            },
                                            0xfffffffffffffff1 => unsafe {
                                                *(args[1] as *mut u64) = ext.address;
                                                args[4] &= !0x1;
                                            },
                                            _ => {}
                                        }

                                        debug!(
                                            "replay {}: Forwarding syscall {:x}(0x{:x?})",
                                            self.event_idx, num, args
                                        );
                                        unsafe {
                                            asm!(
                                                "svc #0x80",
                                                "mov {ret0}, x0",
                                                "mov {ret1}, x1",
                                                "mrs {cflags}, NZCV",
                                                in("x0") args[0],
                                                in("x1") args[1],
                                                in("x2") args[2],
                                                in("x3") args[3],
                                                in("x4") args[4],
                                                in("x5") args[5],
                                                in("x6") args[6],
                                                in("x7") args[7],
                                                in("x8") args[8],
                                                in("x9") args[9],
                                                in("x10") args[10],
                                                in("x11") args[11],
                                                in("x12") args[12],
                                                in("x13") args[13],
                                                in("x14") args[14],
                                                in("x15") args[15],
                                                in("x16") num,
                                                ret0 = out(reg) ret0,
                                                ret1 = out(reg) ret1,
                                                cflags = out(reg) cflags,
                                            );
                                        }
                                        match num {
                                            0xc5 => {
                                                let addr = ret0;
                                                if addr != ext.address {
                                                    error!(
                                                        "replay {}: address mismatch: expected 0x{:x}, got 0x{:x}",
                                                        self.event_idx,
                                                        ext.address, addr
                                                    );
                                                }
                                            }
                                            0xfffffffffffffff6 => unsafe {
                                                let addr = *(args[1] as *mut u64);
                                                if addr != ext.address {
                                                    error!(
                                                        "replay {}: address mismatch: expected 0x{:x}, got 0x{:x}",
                                                        self.event_idx,
                                                        ext.address, addr
                                                    );
                                                }
                                            },
                                            0xfffffffffffffff1 => unsafe {
                                                let addr = *(args[1] as *mut u64);
                                                if addr != ext.address {
                                                    error!(
                                                        "replay {}: address mismatch: expected 0x{:x}, got 0x{:x}",
                                                        self.event_idx,
                                                        ext.address, addr
                                                    );
                                                }
                                            },
                                            _ => {}
                                        }
                                    }
                                    _ => {
                                        error!(
                                            "replay {}: unexpected side effect kind: {:?}",
                                            self.event_idx, side_effect.kind
                                        );
                                        return Ok(ExitKind::Exit);
                                    }
                                }
                            }
                        }
                        //Some(crate::recordable::log_event::Event::MachTrap(trap)) => {}
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

            match num {
                0xc5 => {
                    // mmap
                    // applevisor (and therefore the round_phys_page macro) assumes 64k pages which isn't correct
                    let size = ((args[1] + (0x4000 - 1)) & !(0x4000 - 1)) as usize;
                    trace!("1:1 map of {:x} {:x} due to mmap", ret0, size);
                    vma.map_1to1(ret0, size, av::MemPerms::RWX)?;
                    self.mappings.push((ret0, size));
                    side_effects.push(recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::External(
                            recordable::side_effect::External { address: ret0 },
                        )),
                    });
                    let mut data = vec![0; size];
                    vma.read(ret0, &mut data)?;
                    side_effects.push(recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::Memory(
                            recordable::side_effect::Memory {
                                address: ret0,
                                value: data,
                            },
                        )),
                    });
                }
                0xfffffffffffffff6 => {
                    // mach_vm_allocate
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!(
                        "1:1 map of {:x} {:x} due to mach_vm_allocate",
                        addr,
                        args[2]
                    );
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                    self.mappings.push((addr, args[2] as usize));
                    side_effects.push(recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::External(
                            recordable::side_effect::External { address: addr },
                        )),
                    });
                }
                0xfffffffffffffff1 => {
                    // mach_vm_map
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!("1:1 map of {:x} {:x} due to mach_vm_map", addr, args[2]);
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                    self.mappings.push((addr, args[2] as usize));
                    side_effects.push(recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::External(
                            recordable::side_effect::External { address: addr },
                        )),
                    });
                }
                _ => {}
            }
        }

        let cpsr = (vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | cflags;

        match self.mode {
            Mode::Record => {
                side_effects.extend(vec![
                    recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::Register(
                            recordable::side_effect::Register {
                                register: av::Reg::X0 as _,
                                value: ret0,
                            },
                        )),
                    },
                    recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::Register(
                            recordable::side_effect::Register {
                                register: av::Reg::X1 as _,
                                value: ret1,
                            },
                        )),
                    },
                    recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::Register(
                            recordable::side_effect::Register {
                                register: av::Reg::CPSR as _,
                                value: cpsr,
                            },
                        )),
                    },
                ]);

                for (address, contents) in changed_pages {
                    side_effects.push(recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::Memory(
                            recordable::side_effect::Memory {
                                address,
                                value: contents,
                            },
                        )),
                    });
                }

                if num != 0x3  // read
                    && num != 396  // read_nocancel
                    && num != 0xc5 // mmap
                    && num != 0xfffffffffffffff6  // vm_write
                    && num != 0xfffffffffffffff1
                // vm_map
                {
                    side_effects = vec![recordable::SideEffect {
                        kind: Some(recordable::side_effect::Kind::External(
                            recordable::side_effect::External { address: 0 },
                        )),
                    }];
                }

                // TODO: is there a reason to distinguish between syscall and trap at all?
                //if num < 0x8_0000_0000 {
                // syscall
                self.trace.events.push(recordable::LogEvent {
                    pc: elr,
                    register_state: args.to_vec(),
                    event: Some(recordable::log_event::Event::Syscall(
                        recordable::syscall::Syscall {
                            syscall_number: num as _,
                            side_effects,
                        },
                    )),
                });
                /*
                } else {
                    // trap
                    self.trace.events.push(recordable::LogEvent {
                        pc: elr,
                        register_state: args.to_vec(),
                        event: Some(recordable::log_event::Event::MachTrap(
                            recordable::mach_trap::MachTrap {
                                trap_number: num as _,
                                side_effects,
                            },
                        )),
                    });
                }
                */
            }
            Mode::Replay => {
                self.event_idx += 1;
            }
        }

        debug!("Returning {:x} {:x} {:x}", ret0, ret1, cpsr);
        vcpu.set_reg(av::Reg::X0, ret0)?;
        vcpu.set_reg(av::Reg::X1, ret1)?;
        vcpu.set_reg(av::Reg::CPSR, cpsr)?;
        vcpu.set_reg(av::Reg::PC, elr)?;

        Ok(ExitKind::Continue)
    }
}
