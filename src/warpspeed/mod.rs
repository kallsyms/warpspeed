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
use crate::recordable::side_effects;
use crate::recordable::syscall::mig;
use crate::recordable::syscall::sysno;

// https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/kern_return.h#L325
const KERN_SUCCESS: u64 = 0;
const KERN_DENIED: u64 = 53;
const KERN_NOT_FOUND: u64 = 56;

struct mach_msg_header_t {
    msgh_bits: u32,
    msgh_size: u32,
    msgh_remote_port: u32,
    msgh_local_port: u32,
    msgh_reserved: u32,
    msgh_id: u32,
}
struct mig_reply_error_t {
    hdr: mach_msg_header_t,
    ndr: u64,
    ret_code: u32,
}

fn check_ptr(vma: &VirtMemAllocator, ptr: u64, valid_pages: &mut HashSet<u64>) -> bool {
    if valid_pages.contains(&(ptr & !0xfff)) && valid_pages.contains(&((ptr + 7) & !0xfff)) {
        return true;
    }
    if vma.read_qword(ptr).is_ok() {
        valid_pages.insert(ptr & !0xfff);
        valid_pages.insert((ptr + 7) & !0xfff);
        return true;
    }
    return false;
}

// Explore from the given set of potential pointers, returning a set of pages that are
// accessible from the set of pointers.
// Currently recurses up to 2 levels deep, as I can't think of any syscalls which would
// pointer chase more than that.
fn explore_pointers(vma: &VirtMemAllocator, entry_points: &[u64]) -> HashSet<u64> {
    // TODO: we should get a list of allocations from AppBox and use that.
    let mut valid_pages = HashSet::new();
    let mut queue = entry_points
        .iter()
        .filter_map(|&addr| {
            if check_ptr(vma, addr, &mut valid_pages) {
                Some((addr, 0))
            } else {
                None
            }
        })
        .collect::<VecDeque<_>>();
    let mut pages = HashSet::from_iter(queue.iter().map(|&(addr, _)| addr & !0xfff));

    while let Some((start_addr, depth)) = queue.pop_front() {
        // TODO: we can probably safely assume alignment here
        // TODO: +0x200 is arbitrary
        for addr in start_addr..start_addr + 0x200 {
            // +0x200 can take us to a new, potentially unmapped page so we have to check.
            // But we only have to do this when crossing the page boundry, not every time.
            if (addr + 7) & !0xfff != addr & !0xfff {
                if !check_ptr(vma, addr, &mut valid_pages) {
                    break;
                }
                pages.insert((addr + 7) & !0xfff);
            }
            let maybe_ptr = vma.read_qword(addr).unwrap();
            if !vma.read_byte(maybe_ptr).is_ok() {
                continue;
            }
            let ptr_page_addr = maybe_ptr & !0xfff;
            if !pages.contains(&ptr_page_addr) {
                pages.insert(ptr_page_addr);
                if depth < 2 {
                    queue.push_back((maybe_ptr, depth + 1));
                }
            }
        }
    }

    pages
}

fn forward_syscall(num: u64, args: &[u64; 16]) -> (u64, u64, u64) {
    let mut ret0: u64 = 0;
    let mut ret1: u64 = 0;
    let mut cflags: u64 = 0;

    debug!("Forwarding syscall 0x{:x}(0x{:x?})", num, args);
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

    (ret0, ret1, cflags)
}

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

    mappings: Vec<(u64, usize)>,
    map_fixed_next: u64,
    tsd: u64,
}

impl Warpspeed {
    pub fn new(trace: recordable::Trace, mode: Mode) -> Self {
        Self {
            trace,
            mode,
            event_idx: 0,
            mappings: vec![],
            map_fixed_next: 0x5_0000_0000, // 0x1_0000_0000 above allocation base in appbox
            tsd: 0,
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
        debug!(
            "{}: Incoming syscall 0x{:x}(0x{:x?})",
            self.event_idx, num, args
        );

        let mut ret0: u64 = 0;
        let mut ret1: u64 = 0;
        let mut cflags: u64 = 0;
        let mut side_effects = recordable::SideEffects::default();

        // Stage 1: handle syscalls that need special handling.
        // Optionally also useful for tossing in debugging statements on specific syscalls.
        let mut handled = false;

        // See https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master
        // and https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/syscall_sw.c#L105
        // for numbering.
        // See https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/arm64/sleh.c#L1686
        // for dispatch code.
        match num {
            sysno::SYS_exit => {
                return Ok(ExitKind::Exit);
            }
            sysno::SYS_munmap => {
                // TODO: actually remove from vma.
                // TODO: handle partial unmapping
                if let Some(mapping_idx) = self
                    .mappings
                    .iter()
                    .position(|&(va, len)| va == args[0] && len as u64 == args[1])
                {
                    trace!("munmap({:x}, {:x})", args[0], args[1]);
                    self.mappings.remove(mapping_idx);
                }
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            sysno::SYS_mprotect => {
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            sysno::SYS_mmap => {
                // page align size
                args[1] = (args[1] + (0x4000 - 1)) & !(0x4000 - 1);
                // fake fixed address
                if args[3] & nix::libc::MAP_FIXED as u64 == 0 {
                    args[3] |= nix::libc::MAP_FIXED as u64;
                    trace!("Fixing mmap address to {:x}", self.map_fixed_next);
                    args[0] = self.map_fixed_next;
                    self.map_fixed_next += args[1];
                }
            }
            sysno::TRAP_mach_vm_allocate => {
                // TODO: ensure task is ourselves
                // page align size
                args[2] = (args[2] + (0x4000 - 1)) & !(0x4000 - 1);
                // fake fixed address
                // Check for VM_FLAGS_ANYWHERE being set
                if args[3] & 1 != 0 {
                    args[3] &= !1;
                    trace!(
                        "Fixing mach_vm_allocate address to {:x}",
                        self.map_fixed_next
                    );
                    unsafe { *(args[1] as *mut u64) = self.map_fixed_next };
                    self.map_fixed_next += args[2];
                }
            }
            sysno::TRAP_mach_vm_map => {
                // TODO: ensure task is ourselves
                // page align size
                args[2] = (args[2] + (0x4000 - 1)) & !(0x4000 - 1);
                // fake fixed address
                // Check for VM_FLAGS_ANYWHERE being set
                if args[4] & 1 != 0 {
                    args[4] &= !1;
                    // If a mask is set greater than the 16k page we align to,
                    // bump map_fixed_next to the next correctly aligned address.
                    if args[3] > 0x3fff {
                        self.map_fixed_next = (self.map_fixed_next + args[3]) & !args[3];
                    }
                    trace!("Fixing mach_vm_map address to {:x}", self.map_fixed_next);
                    unsafe { *(args[1] as *mut u64) = self.map_fixed_next };
                    self.map_fixed_next += args[2];
                }
            }
            sysno::TRAP_mach_vm_protect => {
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            sysno::TRAP_mach_vm_deallocate => {
                // TODO: handle partial unmapping
                if let Some(mapping_idx) = self
                    .mappings
                    .iter()
                    .position(|&(va, len)| va == args[1] && len as u64 == args[2])
                {
                    trace!("mach_vm_deallocate({:x}, {:x})", args[1], args[2]);
                    self.mappings.remove(mapping_idx);
                }
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            sysno::SYS_shm_open => {
                // TODO: why was this needed?
                // Maybe shm isn't allowed to be mapped into VM?
                let name = unsafe { CStr::from_ptr(args[0] as _) };
                trace!("shm_open({})", name.to_string_lossy());
                if name.to_string_lossy() == "com.apple.featureflags.shm" {
                    debug!("Denying shm_open for featureflag");
                    ret0 = KERN_DENIED;
                    ret1 = 0;
                    cflags = 1 << 29; // bit 29 (carry flag) is set when an error occurs.
                    handled = true;
                }
                ret0 = KERN_DENIED;
                ret1 = 0;
                cflags = 1 << 29; // bit 29 (carry flag) is set when an error occurs.
                handled = true;
            }
            sysno::SYS_shared_region_check_np => {
                // Return where we loaded the dyld shared cache.
                // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/vm/vm_unix.c#L2017
                if args[0] != u64::MAX {
                    debug!(
                        "Returning {:x} for shared_region_check_np",
                        load_info.shared_cache_base
                    );
                    unsafe {
                        *(args[0] as *mut u64) = load_info.shared_cache_base;
                    }
                }
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            sysno::SYS_proc_info => {
                // This should be ignored by the host anyways
                // (https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/kern/task.c#L740)
                // but stub it out for good measure.
                if args[0] == 0xf {
                    debug!("Stubbing out proc_info for PROC_INFO_CALL_SET_DYLD_IMAGES");
                    ret0 = 0;
                    ret1 = 0;
                    cflags = 0;
                    handled = true;
                }
            }
            sysno::TRAP_mach_msg2 => {
                // We need to stub a few messages here.
                // See https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/mach_traps.h#L465
                // for trap argument layout.
                let msgh_id = args[4] >> 32;
                match msgh_id {
                    // task_info with TASK_DYLD_INFO. Return NOT_FOUND.
                    // Subsystem task (3400), 6th routine so id 3405.
                    // https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/task.defs#L69
                    3405 => {
                        let flavor: u32 = unsafe { *((args[0] + 0x20) as *const u32) };
                        if flavor == 0x11 {
                            debug!("Returning NOT_FOUND for task_info flavor TASK_DYLD_INFO");
                            ret0 = KERN_NOT_FOUND;
                            ret1 = 0;
                            cflags = 1 << 29;
                            handled = true;
                        }
                    }
                    // mach_vm_map
                    // https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/mach_vm.defs#L352
                    4811 => unsafe {
                        let req = args[0] as *mut mig::mach_vm::__Request___kernelrpc_mach_vm_map_t;
                        (*req).size = ((*req).size + (0x4000 - 1)) & !(0x4000 - 1);
                        if (*req).flags & 1 != 0 {
                            (*req).flags &= !1;
                            // If a mask is set greater than the 16k page we align to,
                            // bump map_fixed_next to the next correctly aligned address.
                            if (*req).mask > 0x3fff {
                                self.map_fixed_next =
                                    (self.map_fixed_next + (*req).mask) & !(*req).mask;
                            }
                            let size = (*req).size;
                            trace!(
                                "Fixing kernelrpc_mach_vm_map address to {:x} ({:?})",
                                self.map_fixed_next,
                                *req
                            );
                            (*req).address = self.map_fixed_next;
                            self.map_fixed_next += (*req).size;
                        }
                    },
                    // task_restartable_ranges_register. Fake return SUCCESS.
                    // Subsystem task_restartable (8000), 0th routine.
                    8000 => {
                        debug!("Returning KERN_SUCCESS for task_restartable_ranges_register");
                        unsafe {
                            let reply = args[0] as *mut mig_reply_error_t;
                            // Incoming msgh_bits is 0x1513.
                            // On a real system, reply is 0x1200.
                            // idk, maybe the remote bits (0x13=MACH_MSG_TYPE_COPY_SEND) gets reduced to
                            // MACH_MSG_TYPE_PORT_SEND (0x12)?
                            (*reply).hdr.msgh_bits = 0x1200;
                            (*reply).hdr.msgh_size = 36;
                            (*reply).hdr.msgh_remote_port = 0;
                            // don't need to touch msgh_local_port
                            (*reply).hdr.msgh_reserved = 0;
                            (*reply).hdr.msgh_id = (*reply).hdr.msgh_id + 100;
                            (*reply).ndr = 0x100000000;
                            (*reply).ret_code = KERN_SUCCESS as _;
                        }
                        ret0 = KERN_SUCCESS;
                        ret1 = 0;
                        cflags = 0;
                        handled = true;
                    }
                    _ => {}
                }
            }
            0x8000_0000 => {
                // platform_syscall
                let code = args[3];
                match code {
                    2 => {
                        // set_cthread_self (set tsd/tpidrro)
                        self.tsd = args[0];
                        handled = true;
                    }
                    3 => {
                        // get_cthread_self (get tsd/tpidrro)
                        ret0 = self.tsd;
                        handled = true;
                    }
                    _ => {
                        warn!("Unknown platform syscall {}", code);
                    }
                }
            }
            _ => {}
        }

        // Stage 2: do the syscall.
        // If recording:
        //   1. Snapshot "reachable" memory before the syscall
        //   2. Perform the syscall
        //   3. Diff previously stored reachable pages now that the syscall is done, recording what memory changed.
        // If replaying, make sure we're in the correct place and simply apply the side effects.
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

                    (ret0, ret1, cflags) = forward_syscall(num, &args);

                    // Special case easy syscalls, especially those which could
                    // modify a significant (>1 page) amount of memory.
                    match num {
                        sysno::SYS_read
                        | sysno::SYS_pread
                        | sysno::SYS_read_nocancel
                        | sysno::SYS_pread_nocancel => {
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

                            let side_effects = syscall.side_effects.as_ref().unwrap();

                            // N.B. Do syscall first if required, as it may e.g. allocate memory
                            // that we then need to write into below.
                            if side_effects.external {
                                trace!("Replay syscall index {}", self.event_idx);
                                (ret0, ret1, cflags) = forward_syscall(num, &args);
                            }

                            for reg in &side_effects.registers {
                                trace!("Setting X{:?} to 0x{:x}", reg.register, reg.value);
                                match reg.register {
                                    0x0 => {
                                        if side_effects.external && ret0 != reg.value {
                                            error!(
                                                "Replay {}: syscall return value 0 mismatch: expected 0x{:x}, got 0x{:x}",
                                                self.event_idx, reg.value, ret0
                                            );
                                        }
                                        ret0 = reg.value
                                    }
                                    0x1 => {
                                        if side_effects.external && ret1 != reg.value {
                                            error!(
                                                "Replay {}: syscall return value 1 mismatch: expected 0x{:x}, got 0x{:x}",
                                                self.event_idx, reg.value, ret1
                                            );
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
                            for mem in &side_effects.memory {
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

            // Stage 2.5: map newly allocated memory into the VM as necessary.
            match num {
                sysno::SYS_mmap => {
                    trace!("1:1 map of {:x} {:x} due to mmap", ret0, args[1]);
                    vma.map_1to1(ret0, args[1] as _, av::MemPerms::RWX)?;
                    self.mappings.push((ret0, args[1] as _));

                    side_effects.external = true;

                    // TODO: if this is mapped RO, when we go to replay this side effect
                    // we'll segfault.
                    // let mut data = vec![0; args[1] as _];
                    // vma.read(ret0, &mut data)?;
                    // side_effects.memory.push(recordable::side_effects::Memory {
                    //     address: ret0,
                    //     value: data,
                    // });
                }
                sysno::TRAP_mach_vm_allocate => {
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!(
                        "1:1 map of {:x} {:x} due to mach_vm_allocate",
                        addr,
                        args[2]
                    );

                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                    self.mappings.push((addr, args[2] as usize));

                    side_effects.external = true;
                }
                sysno::TRAP_mach_vm_map => {
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!("1:1 map of {:x} {:x} due to mach_vm_map", addr, args[2]);
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                    self.mappings.push((addr, args[2] as usize));

                    side_effects.external = true;
                    // TODO: record memory contents?
                }
                sysno::TRAP_mach_msg2 => {
                    // We need to stub a few messages here.
                    // See https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/mach_traps.h#L465
                    // for trap argument layout.
                    let msgh_id = args[4] >> 32;
                    match msgh_id {
                        // mach_vm_map
                        4811 => {
                            let reply = unsafe {
                                *(args[0] as *const mig::mach_vm::__Reply___kernelrpc_mach_vm_map_t)
                            };
                            let addr = reply.address;
                            // TODO: this should be saved before syscall.
                            // only works because this happens to not be overwritten
                            let size = unsafe {
                                (*(args[0]
                                    as *const mig::mach_vm::__Request___kernelrpc_mach_vm_map_t))
                                    .size
                            };
                            trace!(
                                "1:1 map of {:x} {:x} due to __kernelrpc_mach_vm_map",
                                addr,
                                size
                            );
                            vma.map_1to1(addr, size as usize, av::MemPerms::RWX)?;
                            self.mappings.push((addr, size as usize));

                            side_effects.external = true;
                            // TODO: record memory contents?
                        }
                        _ => {}
                    }
                }
                _ => {}
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
            // TODO: open/close are needed so mmapping fds works, but these shouldn't be needed.
            if num == sysno::SYS_open || num == sysno::SYS_close || num == sysno::SYS_write_nocancel
            {
                side_effects.external = true;
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

        debug!("Returning {:x} {:x} {:x}", ret0, ret1, cpsr);
        vcpu.set_reg(av::Reg::X0, ret0)?;
        vcpu.set_reg(av::Reg::X1, ret1)?;
        vcpu.set_reg(av::Reg::CPSR, cpsr)?;
        vcpu.set_reg(av::Reg::PC, elr)?;
        vcpu.set_sys_reg(av::SysReg::TPIDRRO_EL0, self.tsd)?;

        Ok(ExitKind::Continue)
    }
}
