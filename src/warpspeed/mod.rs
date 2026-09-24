use anyhow::{Context, Result};
use appbox::hyperpom::error::{Error as HyperpomError, MemoryError};
use appbox::hyperpom::memory::VirtMemAllocator;
use log::{debug, error, trace};
use std::collections::HashMap;

use appbox::applevisor as av;
use appbox::guest::{
    Decision, GuestEnd, GuestFault, Outcome, Preemption, Registers, Returned, Syscall, ThreadCx,
    ThreadId, ThreadSwitch, ThreadingModel,
};
use appbox::syscalls;
use appbox::trap::{explore_pointers, forward_syscall};

use crate::recordable;
use crate::recordable::scheduling;
use crate::recordable::side_effects;
use crate::shared_files::{self, FdState, ShadowFile};

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

type PageSnapshot = HashMap<u64, Vec<u8>>;

fn snapshot_pages(vma: &VirtMemAllocator, args: &[u64; 16]) -> Result<PageSnapshot> {
    let mut pages = HashMap::new();
    for page_addr in explore_pointers(vma, args) {
        let mut contents: Vec<u8> = vec![0; 0x1000];
        vma.read(page_addr, &mut contents)?;
        pages.insert(page_addr, contents);
    }
    Ok(pages)
}

fn diff_pages(vma: &VirtMemAllocator, before: PageSnapshot) -> Result<Vec<side_effects::Memory>> {
    let mut changes = vec![];
    for (page_addr, old_contents) in before {
        let mut new_contents: Vec<u8> = vec![0; 0x1000];
        match vma.read(page_addr, &mut new_contents) {
            Ok(_) => {}
            // Unmapped by the syscall (e.g. munmap), which replay re-executes.
            Err(HyperpomError::Memory(MemoryError::UnallocatedMemoryAccess(_))) => continue,
            Err(err) => return Err(err.into()),
        }
        changes.extend(diff_memory(page_addr, &old_contents, &new_contents));
    }
    Ok(changes)
}

fn apply_memory(memory: &[side_effects::Memory]) {
    for mem in memory {
        trace!("Writing to 0x{:x}", mem.address);
        unsafe {
            std::ptr::copy(mem.value.as_ptr(), mem.address as _, mem.value.len());
        }
    }
}

fn registers_to_proto(regs: &Registers) -> scheduling::Registers {
    scheduling::Registers {
        x: regs.x.to_vec(),
        sp: regs.sp,
        pc: regs.pc,
        cpsr: regs.cpsr,
        q: regs.q.iter().map(|q| q.to_le_bytes().to_vec()).collect(),
        fpcr: regs.fpcr,
        fpsr: regs.fpsr,
        tpidr: regs.tpidr,
        tpidrro: regs.tpidrro,
    }
}

fn registers_from_proto(regs: &scheduling::Registers) -> Result<Registers> {
    Ok(Registers {
        x: regs.x.as_slice().try_into().context("wrong number of X registers")?,
        sp: regs.sp,
        pc: regs.pc,
        cpsr: regs.cpsr,
        q: regs
            .q
            .iter()
            .map(|q| Ok(u128::from_le_bytes(q.as_slice().try_into()?)))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong number of Q registers"))?,
        fpcr: regs.fpcr,
        fpsr: regs.fpsr,
        tpidr: regs.tpidr,
        tpidrro: regs.tpidrro,
    })
}

/// A syscall a thread left the vCPU in, whose results come when it's switched back to.
#[derive(Clone)]
struct PendingSyscall {
    num: u64,
    args: [u64; 16],
    /// Recording only: memory the syscall might write, as it was when the syscall began.
    before_pages: PageSnapshot,
}

#[cfg(test)]
mod tests {
    use super::diff_memory;
    use crate::recordable::side_effects;

    #[test]
    fn diff_memory_returns_no_ranges_when_pages_match() {
        let page = 0x1000;
        let old = [0u8; 8];
        let new = [0u8; 8];

        assert!(diff_memory(page, &old, &new).is_empty());
    }

    #[test]
    fn diff_memory_returns_single_range_for_contiguous_change() {
        let page = 0x2000;
        let old = [0, 1, 2, 3, 4, 5];
        let new = [0, 1, 9, 8, 7, 5];

        assert_eq!(
            diff_memory(page, &old, &new),
            vec![side_effects::Memory {
                address: page + 2,
                value: vec![9, 8, 7],
            }]
        );
    }

    #[test]
    fn diff_memory_splits_disjoint_changes() {
        let page = 0x3000;
        let old = [1, 2, 3, 4, 5, 6, 7];
        let new = [1, 9, 8, 4, 5, 0, 7];

        assert_eq!(
            diff_memory(page, &old, &new),
            vec![
                side_effects::Memory {
                    address: page + 1,
                    value: vec![9, 8],
                },
                side_effects::Memory {
                    address: page + 5,
                    value: vec![0],
                },
            ]
        );
    }

    #[test]
    fn diff_memory_captures_changes_at_start_and_end() {
        let page = 0x4000;
        let old = [1, 2, 3, 4, 5];
        let new = [7, 2, 3, 4, 9];

        assert_eq!(
            diff_memory(page, &old, &new),
            vec![
                side_effects::Memory {
                    address: page,
                    value: vec![7],
                },
                side_effects::Memory {
                    address: page + 4,
                    value: vec![9],
                },
            ]
        );
    }

    #[test]
    #[should_panic]
    fn diff_memory_requires_equal_sized_inputs() {
        let _ = diff_memory(0x5000, &[1, 2], &[1]);
    }
}

/// Where a recording or replay is, which a checkpoint must capture to go back to.
#[derive(Clone)]
pub struct ReplayState {
    event_idx: usize,
    /// Replay only: the thread on the vCPU.
    current_tid: ThreadId,
    /// The VM's count of guest instructions at the last event (see `Preemption.instructions`).
    last_event_instructions: u64,
    pending: HashMap<ThreadId, PendingSyscall>,
    fd_table: HashMap<i32, FdState>,
}

impl ReplayState {
    /// The index of the next event to record or replay.
    pub fn event_index(&self) -> usize {
        self.event_idx
    }
}

/// The syscall under way, between [`Hooks::syscall`](appbox::guest::Hooks::syscall) and
/// `syscall_done`.
enum InSyscall {
    /// Recording: the thread that made it, and the memory it might write as it was before.
    Recording { tid: ThreadId, before_pages: PageSnapshot },
    /// Replay: appbox is handling it, as when recording; the results are the recording's.
    External {
        syscall: recordable::syscall::Syscall,
        num: u64,
        args: [u64; 16],
        /// The thread's TSD base, which appbox doesn't know on replay (see `replay_syscall`).
        tpidrro: u64,
    },
    /// Replay: replayed from the recording alone.
    Replayed,
}

pub struct Warpspeed {
    pub trace: recordable::Trace,
    state: ReplayState,
    in_syscall: Option<InSyscall>,
    /// Replay only: events before this were already replayed once, so their writes to
    /// stdout/stderr aren't repeated.
    quiet_until: usize,
    /// Replay only: the guest memory the last event's recorded side effects wrote.
    event_writes: Vec<(u64, usize)>,
    shared_file_ids_by_identity: HashMap<(u64, u64), u64>,
    shared_files_by_id: HashMap<u64, recordable::trace::SharedFile>,
    shadow_files: HashMap<u64, ShadowFile>,
}

/// Recording and replaying rely on the guest's threads taking turns on one vCPU.
pub fn ensure_time_shared(t: &ThreadCx) -> Result<()> {
    anyhow::ensure!(
        t.handler().threading() == ThreadingModel::TimeShared,
        "recording and replaying need the guest's threads time-shared, not in parallel"
    );
    Ok(())
}

/// Logs a fault the guest took, and where.
pub fn log_fault(t: &ThreadCx, fault: &GuestFault) {
    error!(
        "Guest fault: {:?} at {:#x} (syndrome={:#x}, address={:x?})",
        fault.kind, fault.pc, fault.syndrome, fault.address
    );
    for (idx, addr) in t.stack(64).iter().enumerate() {
        match t.symbolicate(*addr) {
            Some(sym) => error!(
                "{:02} 0x{:016x} {}::{} + 0x{:x}",
                idx,
                addr,
                sym.image,
                sym.symbol,
                addr - sym.symbol_addr
            ),
            None => error!("{:02} 0x{:016x}", idx, addr),
        }
    }
}

/// Sets the registers a syscall returns in, once it has returned.
fn set_returned(vcpu: &av::Vcpu, returned: &Returned) -> Result<()> {
    let cpsr = (vcpu.get_reg(av::Reg::CPSR)? & !(0b1111 << 28)) | returned.flags;
    vcpu.set_reg(av::Reg::X0, returned.x0)?;
    vcpu.set_reg(av::Reg::X1, returned.x1)?;
    vcpu.set_reg(av::Reg::CPSR, cpsr)?;
    Ok(())
}

impl Warpspeed {
    pub fn new(trace: recordable::Trace) -> Result<Self> {
        let shared_file_ids_by_identity = trace
            .shared_files
            .iter()
            .map(|shared_file| {
                (
                    (shared_file.device, shared_file.inode),
                    shared_file.id,
                )
            })
            .collect::<HashMap<_, _>>();
        let shared_files_by_id = trace
            .shared_files
            .iter()
            .cloned()
            .map(|shared_file| (shared_file.id, shared_file))
            .collect::<HashMap<_, _>>();

        Ok(Self {
            trace,
            state: ReplayState {
                event_idx: 0,
                current_tid: 0,
                last_event_instructions: 0,
                pending: HashMap::new(),
                fd_table: HashMap::new(),
            },
            in_syscall: None,
            quiet_until: 0,
            event_writes: Vec::new(),
            shared_file_ids_by_identity,
            shared_files_by_id,
            shadow_files: HashMap::new(),
        })
    }

    fn syscall_failed(cflags: u64) -> bool {
        cflags & (1 << 29) != 0
    }

    fn fd_arg_for_shared_file_syscall(num: u64, args: &[u64; 16]) -> Option<i32> {
        match num {
            syscalls::SYS_write
            | syscalls::SYS_write_nocancel
            | syscalls::SYS_pwrite
            | syscalls::SYS_pwrite_nocancel
            | syscalls::SYS_ftruncate => Some(args[0] as i32),
            _ => None,
        }
    }

    fn shared_file_id_for_fd(&self, fd: i32) -> Option<u64> {
        let state = self.state.fd_table.get(&fd)?;
        self.shared_file_ids_by_identity
            .get(&(state.device, state.inode))
            .copied()
    }

    fn update_fd_table(&mut self, num: u64, args: &[u64; 16], ret0: u64, cflags: u64) -> Result<()> {
        if Self::syscall_failed(cflags) {
            return Ok(());
        }

        match num {
            syscalls::SYS_open
            | syscalls::SYS_openat
            | syscalls::SYS_open_nocancel
            | syscalls::SYS_openat_nocancel => {
                let fd = ret0 as i32;
                self.state.fd_table.insert(fd, FdState::from_fd(fd)?);
            }
            syscalls::SYS_dup => {
                let src = args[0] as i32;
                let dst = ret0 as i32;
                if let Some(state) = self.state.fd_table.get(&src).cloned() {
                    self.state.fd_table.insert(dst, state);
                }
            }
            syscalls::SYS_dup2 => {
                let src = args[0] as i32;
                let dst = ret0 as i32;
                if let Some(state) = self.state.fd_table.get(&src).cloned() {
                    self.state.fd_table.insert(dst, state);
                }
            }
            syscalls::SYS_close | syscalls::SYS_close_nocancel => {
                self.state.fd_table.remove(&(args[0] as i32));
            }
            _ => {}
        }

        Ok(())
    }

    fn record_shared_map(
        &mut self,
        num: u64,
        args: &[u64; 16],
        cflags: u64,
    ) -> Result<Option<recordable::syscall::syscall::SharedMap>> {
        if num != syscalls::SYS_mmap || Self::syscall_failed(cflags) {
            return Ok(None);
        }

        let flags = args[3] as i32;
        if flags & nix::libc::MAP_SHARED == 0 || flags & nix::libc::MAP_ANON != 0 {
            return Ok(None);
        }

        let fd = args[4] as i32;
        if fd < 0 {
            return Ok(None);
        }

        let fd_state = self
            .state
            .fd_table
            .get(&fd)
            .cloned()
            .with_context(|| format!("missing fd tracking for shared mmap fd {}", fd))?;
        if !fd_state.is_regular {
            return Ok(None);
        }

        let identity = (fd_state.device, fd_state.inode);
        let shared_file_id = if let Some(id) = self.shared_file_ids_by_identity.get(&identity) {
            *id
        } else {
            let stat = nix::sys::stat::fstat(fd)
                .with_context(|| format!("fstat failed for shared mmap fd {}", fd))?;
            let contents = shared_files::read_fd_contents(fd, stat.st_size.max(0) as usize)?;
            let id = self.trace.shared_files.len() as u64 + 1;
            let shared_file = recordable::trace::SharedFile {
                id,
                path: fd_state.path,
                device: fd_state.device,
                inode: fd_state.inode,
                size: contents.len() as u64,
                initial_contents: contents,
            };
            self.trace.shared_files.push(shared_file.clone());
            self.shared_file_ids_by_identity.insert(identity, id);
            self.shared_files_by_id.insert(id, shared_file);
            id
        };

        Ok(Some(recordable::syscall::syscall::SharedMap {
            shared_file_id,
            file_offset: args[5],
            map_length: args[1],
            recorded_fd: fd,
        }))
    }

    fn ensure_shadow_file(&mut self, shared_file_id: u64) -> Result<()> {
        if self.shadow_files.contains_key(&shared_file_id) {
            return Ok(());
        }

        let shared_file = self
            .shared_files_by_id
            .get(&shared_file_id)
            .cloned()
            .with_context(|| format!("missing shared file {}", shared_file_id))?;
        let shadow_file = ShadowFile::from_snapshot(&shared_file)?;
        self.shadow_files.insert(shared_file_id, shadow_file);
        Ok(())
    }

    fn rebind_fd_to_shadow_file(&mut self, fd: i32, shared_file_id: u64) -> Result<()> {
        self.ensure_shadow_file(shared_file_id)?;
        let shadow_file = self
            .shadow_files
            .get(&shared_file_id)
            .context("shadow file disappeared unexpectedly")?;
        shared_files::rebind_fd(fd, shadow_file.fd())
    }

    fn prepare_replay_external_syscall(
        &mut self,
        num: u64,
        args: &[u64; 16],
        syscall: &recordable::syscall::Syscall,
    ) -> Result<()> {
        if num == syscalls::SYS_mmap {
            if let Some(shared_map) = &syscall.shared_map {
                self.rebind_fd_to_shadow_file(shared_map.recorded_fd, shared_map.shared_file_id)?;
            }
            return Ok(());
        }

        if let Some(fd) = Self::fd_arg_for_shared_file_syscall(num, args) {
            if let Some(shared_file_id) = self.shared_file_id_for_fd(fd) {
                self.rebind_fd_to_shadow_file(fd, shared_file_id)?;
            }
        }

        Ok(())
    }

    /// Whether a syscall's effects reach outside the guest (or appbox's state), so replay must
    /// re-execute it rather than just apply its recorded side effects.
    fn is_external(&self, num: u64, args: &[u64; 16]) -> bool {
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
            return true;
        }

        // Duplicating descriptors, and close-on-exec flags, which exec relies on.
        if matches!(num, syscalls::SYS_fcntl | syscalls::SYS_fcntl_nocancel)
            && matches!(
                args[1] as i32,
                nix::libc::F_SETFD | nix::libc::F_DUPFD | nix::libc::F_DUPFD_CLOEXEC
            )
        {
            return true;
        }
        if num == syscalls::SYS_ioctl
            && matches!(args[1], nix::libc::FIOCLEX | nix::libc::FIONCLEX)
        {
            return true;
        }

        // Also include write_nocancel so we can see stdout/stderr.
        if num == syscalls::SYS_write_nocancel && (args[0] == 1 || args[0] == 2) {
            return true;
        }

        if let Some(fd) = Self::fd_arg_for_shared_file_syscall(num, args) {
            if self.shared_file_id_for_fd(fd).is_some() {
                return true;
            }
        }

        // And these are needed to get memory mappings correct.
        if num == syscalls::SYS_mmap
            || num == syscalls::SYS_munmap
            || num == syscalls::TRAP_mach_vm_allocate
            || num == syscalls::TRAP_mach_vm_map
            || num == syscalls::TRAP_mach_vm_deallocate
        {
            return true;
        }
        if num == syscalls::TRAP_mach_msg2 {
            let msgh_id = args[4] >> 32;
            if msgh_id == 4811 {
                return true;
            }
        }

        // And finally, exit() so appbox ends the guest.
        if num == syscalls::SYS_exit {
            return true;
        }

        // XXX: kinda hack. platform syscalls dealing with TSD are replayed so appbox's TSD management handles things correctly later
        num == 0x8000_0000
    }

    /// Records the changes appbox made to guest memory itself.
    fn record_guest_memory_changes(
        &mut self,
        t: &mut ThreadCx,
        side_effects: &mut recordable::SideEffects,
    ) -> Result<()> {
        let changes = t.take_guest_memory_changes();
        for (address, size) in changes.allocations {
            side_effects
                .allocations
                .push(side_effects::Allocation { address, size });
        }
        for (address, len) in changes.writes {
            let mut value = vec![0; len as usize];
            t.memory().read(address, &mut value)?;
            side_effects.memory.push(side_effects::Memory { address, value });
        }
        Ok(())
    }

    /// Repeats appbox's allocations on the guest's behalf, which must land where they did.
    fn replay_allocations(
        &mut self,
        t: &mut ThreadCx,
        side_effects: &recordable::SideEffects,
    ) -> Result<()> {
        for allocation in &side_effects.allocations {
            let address = t
                .handler()
                .allocate_guest_memory(&mut t.memory(), allocation.size)?;
            anyhow::ensure!(
                address == allocation.address,
                "replay {}: allocation landed at {:#x}, not {:#x}",
                self.state.event_idx,
                address,
                allocation.address
            );
        }
        Ok(())
    }

    /// Before a syscall: notes what's needed to record it once done.
    pub fn record_syscall(&mut self, t: &ThreadCx, call: &Syscall) -> Result<()> {
        debug!(
            "{}: Incoming syscall ({}) {:x}(x{:x?})",
            self.state.event_idx,
            call.name().unwrap_or("<unknown>"),
            call.number,
            call.args
        );
        self.in_syscall = Some(InSyscall::Recording {
            tid: t.thread(),
            before_pages: snapshot_pages(&t.memory(), &call.args)?,
        });
        Ok(())
    }

    /// Records a syscall, once it's done.
    pub fn record_syscall_done(
        &mut self,
        t: &mut ThreadCx,
        call: &Syscall,
        outcome: &Outcome,
    ) -> Result<()> {
        let Some(InSyscall::Recording { tid, before_pages }) = self.in_syscall.take() else {
            return Ok(());
        };
        let result = self.record_outcome(t, call, outcome, tid, before_pages);
        self.state.last_event_instructions = t.guest_instructions();
        result
    }

    fn record_outcome(
        &mut self,
        t: &mut ThreadCx,
        call: &Syscall,
        outcome: &Outcome,
        tid: ThreadId,
        before_pages: PageSnapshot,
    ) -> Result<()> {
        let (num, args, elr) = (call.number, call.args, call.return_address);
        let (returned, ended) = match outcome {
            Outcome::Returned(returned) => (*returned, false),
            // The process ending (e.g. with its last thread) must happen on replay too.
            Outcome::Ended(GuestEnd::Exited(_)) => (Returned { x0: 0, x1: 0, flags: 0 }, true),
            Outcome::Exec(request) => {
                self.trace.events.push(recordable::LogEvent {
                    pc: elr,
                    register_state: args.to_vec(),
                    tid,
                    event: Some(recordable::log_event::Event::Exec(recordable::Exec {
                        path: request.path.to_string_lossy().into_owned(),
                        argv: request.argv.clone(),
                        envp: request.envp.clone(),
                    })),
                });
                self.state.event_idx += 1;
                return Ok(());
            }
            Outcome::Switched(switch) => {
                return self.record_switch(t, elr, num, &args, tid, before_pages, *switch);
            }
            Outcome::Resumed | Outcome::ThreadExited | Outcome::Ended(GuestEnd::Crashed { .. }) => {
                return Ok(());
            }
        };

        let mut side_effects = recordable::SideEffects::default();
        match num {
            syscalls::SYS_read
            | syscalls::SYS_pread
            | syscalls::SYS_read_nocancel
            | syscalls::SYS_pread_nocancel => {
                let buf = args[1];
                let mut data = vec![0; returned.x0 as usize];
                t.memory().read(buf, &mut data)?;
                side_effects.memory.push(recordable::side_effects::Memory {
                    address: buf,
                    value: data,
                });
            }
            _ => side_effects.memory.extend(diff_pages(&t.memory(), before_pages)?),
        }
        self.record_guest_memory_changes(t, &mut side_effects)?;
        trace!(
            "Changed mem: {:?}",
            side_effects
                .memory
                .iter()
                .map(|m| (m.address, m.address + m.value.len() as u64))
                .collect::<Vec<_>>()
        );
        let shared_map = self.record_shared_map(num, &args, returned.flags)?;

        let cpsr =
            (t.vcpu().get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | returned.flags;
        side_effects.registers.extend([
            recordable::side_effects::Register {
                register: av::Reg::X0 as _,
                value: returned.x0,
            },
            recordable::side_effects::Register {
                register: av::Reg::X1 as _,
                value: returned.x1,
            },
            recordable::side_effects::Register {
                register: av::Reg::CPSR as _,
                value: cpsr,
            },
        ]);
        side_effects.external = self.is_external(num, &args) || ended;

        self.trace.events.push(recordable::LogEvent {
            pc: elr,
            register_state: args.to_vec(),
            tid,
            event: Some(recordable::log_event::Event::Syscall(
                recordable::syscall::Syscall {
                    syscall_number: num as _,
                    side_effects: Some(side_effects),
                    shared_map,
                    descheduled: false,
                },
            )),
        });
        self.update_fd_table(num, &args, returned.x0, returned.flags)?;
        self.state.event_idx += 1;
        debug!(
            "Returning x0={:x} x1={:x} cpsr={:x}",
            returned.x0, returned.x1, cpsr
        );
        Ok(())
    }

    /// Records a syscall `tid` left the vCPU in, and the switch to the next thread.
    #[allow(clippy::too_many_arguments)]
    fn record_switch(
        &mut self,
        t: &mut ThreadCx,
        pc: u64,
        num: u64,
        args: &[u64; 16],
        tid: ThreadId,
        before_pages: PageSnapshot,
        switch: ThreadSwitch,
    ) -> Result<()> {
        let mut side_effects = recordable::SideEffects {
            external: self.is_external(num, args),
            ..Default::default()
        };
        self.record_guest_memory_changes(t, &mut side_effects)?;
        self.trace.events.push(recordable::LogEvent {
            pc,
            register_state: args.to_vec(),
            tid,
            event: Some(recordable::log_event::Event::Syscall(
                recordable::syscall::Syscall {
                    syscall_number: num as _,
                    side_effects: Some(side_effects),
                    shared_map: None,
                    descheduled: true,
                },
            )),
        });
        self.state.pending.insert(
            tid,
            PendingSyscall {
                num,
                args: *args,
                before_pages,
            },
        );

        self.state.event_idx += 1;
        self.record_switch_in(t, tid, switch)
    }

    /// Records the switch from `tid` to the thread now on the vCPU.
    fn record_switch_in(&mut self, t: &ThreadCx, tid: ThreadId, switch: ThreadSwitch) -> Result<()> {
        let registers = t.registers()?;
        let memory = match self.state.pending.remove(&switch.to) {
            Some(pending) => {
                self.complete_pending(&pending, &registers)?;
                diff_pages(&t.memory(), pending.before_pages)?
            }
            None => vec![],
        };
        self.trace.events.push(recordable::LogEvent {
            pc: registers.pc,
            register_state: vec![],
            tid,
            event: Some(recordable::log_event::Event::Scheduling(
                scheduling::Scheduling {
                    tid,
                    event: Some(scheduling::scheduling::Event::Switch(
                        scheduling::scheduling::SwitchCurrent {
                            new_tid: switch.to,
                            registers: Some(registers_to_proto(&registers)),
                            memory,
                        },
                    )),
                },
            )),
        });
        self.state.event_idx += 1;
        Ok(())
    }

    /// Tracks what a thread's pending syscall did now that it has returned with `registers`.
    fn complete_pending(&mut self, pending: &PendingSyscall, registers: &Registers) -> Result<()> {
        self.update_fd_table(pending.num, &pending.args, registers.x[0], registers.cpsr)
    }

    /// Records where a thread was preempted, and the switch to the next one (now on the vCPU).
    pub fn record_preemption(&mut self, t: &mut ThreadCx, preemption: &Preemption) -> Result<()> {
        let tid = preemption
            .switch
            .from
            .context("a preempted thread that had exited")?;
        let mut side_effects = recordable::SideEffects::default();
        self.record_guest_memory_changes(t, &mut side_effects)?;
        self.trace.events.push(recordable::LogEvent {
            pc: preemption.registers.pc,
            register_state: vec![],
            tid,
            event: Some(recordable::log_event::Event::Preemption(
                recordable::Preemption {
                    instructions: preemption.instructions - self.state.last_event_instructions,
                    registers: Some(registers_to_proto(&preemption.registers)),
                    side_effects: Some(side_effects),
                },
            )),
        });
        self.state.event_idx += 1;
        self.record_switch_in(t, tid, preemption.switch)?;
        self.state.last_event_instructions = t.guest_instructions();
        Ok(())
    }

    /// Replays a syscall the current thread left the vCPU in, and the switch to the next thread.
    fn replay_switch(
        &mut self,
        t: &mut ThreadCx,
        num: u64,
        args: &[u64; 16],
        syscall: &recordable::syscall::Syscall,
    ) -> Result<()> {
        let side_effects = syscall.side_effects.as_ref().unwrap();
        if side_effects.external && !self.already_written(num, args) {
            // Only plain forwarded syscalls can block, so there's nothing for appbox to do.
            self.prepare_replay_external_syscall(num, args, syscall)?;
            forward_syscall(num, args);
        }
        self.replay_allocations(t, side_effects)?;
        self.apply_memory(t, &side_effects.memory);
        self.state.pending.insert(
            self.state.current_tid,
            PendingSyscall {
                num,
                args: *args,
                before_pages: HashMap::new(),
            },
        );
        self.state.event_idx += 1;
        self.replay_switch_in(t)
    }

    /// Replays the switch to another thread that the next event records.
    fn replay_switch_in(&mut self, t: &mut ThreadCx) -> Result<()> {
        let event = self
            .trace
            .events
            .get(self.state.event_idx)
            .with_context(|| format!("replay {}: trace ended mid thread switch", self.state.event_idx))?;
        let Some(recordable::log_event::Event::Scheduling(scheduling::Scheduling {
            event: Some(scheduling::scheduling::Event::Switch(switch)),
            ..
        })) = &event.event
        else {
            anyhow::bail!(
                "replay {}: expected a thread switch, got {:?}",
                self.state.event_idx,
                event.event
            );
        };
        let switch = switch.clone();
        let registers = registers_from_proto(
            switch
                .registers
                .as_ref()
                .context("thread switch without registers")?,
        )?;
        t.set_registers(&registers)?;
        self.apply_memory(t, &switch.memory);
        if let Some(pending) = self.state.pending.remove(&switch.new_tid) {
            self.complete_pending(&pending, &registers)?;
        }
        trace!("Replay {}: switched to thread {}", self.state.event_idx, switch.new_tid);
        self.state.current_tid = switch.new_tid;
        self.state.event_idx += 1;
        Ok(())
    }

    /// The current thread's next preemption, if replay's next event is one: how many guest
    /// instructions after the previous event (as counted when recording), and where.
    pub fn next_preemption(&self) -> Option<(u64, Registers)> {
        let event = self.trace.events.get(self.state.event_idx)?;
        let Some(recordable::log_event::Event::Preemption(preemption)) = &event.event else {
            return None;
        };
        let registers = registers_from_proto(preemption.registers.as_ref()?).ok()?;
        (event.tid == self.state.current_tid).then_some((preemption.instructions, registers))
    }

    /// Replays the next event, a preemption, once the guest is where it was preempted: the
    /// switch to the next thread.
    pub fn apply_preemption(&mut self, t: &mut ThreadCx) -> Result<()> {
        let event = self.trace.events[self.state.event_idx].clone();
        let Some(recordable::log_event::Event::Preemption(preemption)) = event.event else {
            anyhow::bail!("replay {}: not a preemption", self.state.event_idx);
        };
        self.event_writes.clear();
        if let Some(side_effects) = &preemption.side_effects {
            self.replay_allocations(t, side_effects)?;
            self.apply_memory(t, &side_effects.memory);
        }
        self.state.event_idx += 1;
        self.replay_switch_in(t)?;
        self.state.last_event_instructions = t.guest_instructions();
        Ok(())
    }

    /// Where replay is (see [`ReplayState`]).
    pub fn state(&self) -> ReplayState {
        self.state.clone()
    }

    /// Puts replay back to `state`, as of a checkpoint the guest was just restored to (with
    /// `instructions` counted so far).
    pub fn set_state(&mut self, state: ReplayState, instructions: u64) {
        self.state = state;
        self.state.last_event_instructions = instructions;
        self.in_syscall = None;
        self.event_writes.clear();
    }

    /// The index of the next event to record or replay.
    pub fn event_index(&self) -> usize {
        self.state.event_idx
    }

    /// The VM's count of guest instructions at the last event.
    pub fn last_event_instructions(&self) -> u64 {
        self.state.last_event_instructions
    }

    /// The guest memory the last event's recorded side effects wrote, as ranges.
    pub fn event_writes(&self) -> &[(u64, usize)] {
        &self.event_writes
    }

    /// Events before `event` were already replayed once, so their writes to stdout/stderr
    /// aren't repeated.
    pub fn set_quiet_until(&mut self, event: usize) {
        self.quiet_until = self.quiet_until.max(event);
    }

    /// Applies recorded writes to guest memory, telling checkpoints first.
    fn apply_memory(&mut self, t: &ThreadCx, memory: &[side_effects::Memory]) {
        let mut vma = t.memory();
        for mem in memory {
            vma.log_host_write(mem.address, mem.value.len());
            self.event_writes.push((mem.address, mem.value.len()));
        }
        apply_memory(memory);
    }

    /// Whether replaying syscall `num` should skip actually doing it, as a write to
    /// stdout/stderr already done.
    fn already_written(&self, num: u64, args: &[u64; 16]) -> bool {
        self.state.event_idx < self.quiet_until
            && num == syscalls::SYS_write_nocancel
            && (args[0] == 1 || args[0] == 2)
    }

    /// Once the guest has exec'd: only the calling thread survives, and close-on-exec
    /// descriptors are gone.
    pub fn exec_done(&mut self, t: &ThreadCx) {
        self.state.last_event_instructions = t.guest_instructions();
        self.state.pending.clear();
        self.state
            .fd_table
            .retain(|&fd, _| unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0);
    }

    /// Replays a syscall: checks it's the one recorded, then either replays it from the
    /// recording, or has appbox do it again (its results are then the recording's, see
    /// [`Self::replay_syscall_done`]).
    pub fn replay_syscall(&mut self, t: &mut ThreadCx, call: &Syscall) -> Result<Decision> {
        let (num, args, elr) = (call.number, call.args, call.return_address);
        trace!("ELR_EL1: {:#x}", elr);
        debug!(
            "{}: Incoming syscall ({}) {:x}(x{:x?})",
            self.state.event_idx,
            call.name().unwrap_or("<unknown>"),
            num,
            args
        );
        let diverged = Decision::End(GuestEnd::Exited(0));
        let tid = self.state.current_tid;
        self.event_writes.clear();
        let Some(event) = self.trace.events.get(self.state.event_idx) else {
            error!("Replay {}: past the end of the recording", self.state.event_idx);
            return Ok(diverged);
        };
        if elr != event.pc {
            error!(
                "Replay {}: pc mismatch: expected 0x{:x}, got 0x{:x}",
                self.state.event_idx, event.pc, elr
            );
            return Ok(diverged);
        }
        if tid != event.tid {
            error!(
                "Replay {}: thread mismatch: expected {}, got {}",
                self.state.event_idx, event.tid, tid
            );
            return Ok(diverged);
        }

        let syscall = match &event.event {
            Some(recordable::log_event::Event::Exec(_)) => {
                self.state.event_idx += 1;
                return Ok(Decision::Default);
            }
            Some(recordable::log_event::Event::Syscall(syscall)) => syscall.clone(),
            _ => {
                error!(
                    "replay {}: unexpected event type: {:?}",
                    self.state.event_idx, event.event
                );
                return Ok(diverged);
            }
        };
        if num != syscall.syscall_number {
            error!(
                "Replay {}: syscall mismatch: expected 0x{:x}, got 0x{:x}",
                self.state.event_idx, syscall.syscall_number, num
            );
        }
        if syscall.descheduled {
            self.replay_switch(t, num, &args, &syscall)?;
            self.in_syscall = Some(InSyscall::Replayed);
            return Ok(Decision::Resumed);
        }

        let side_effects = syscall.side_effects.as_ref().unwrap();
        if side_effects.external && !self.already_written(num, &args) {
            self.prepare_replay_external_syscall(num, &args, &syscall)?;
            trace!("Replay syscall index {}", self.state.event_idx);
            self.in_syscall = Some(InSyscall::External {
                tpidrro: t.vcpu().get_sys_reg(av::SysReg::TPIDRRO_EL0)?,
                syscall,
                num,
                args,
            });
            return Ok(Decision::Default);
        }

        let Some(returned) = self.recorded_return(&syscall, None) else {
            return Ok(diverged);
        };
        self.replay_side_effects(t, &syscall, num, &args, &returned)?;
        self.in_syscall = Some(InSyscall::Replayed);
        Ok(Decision::Return(returned))
    }

    /// What a syscall returned when recorded (checked against what appbox just returned, if it
    /// did it again).
    fn recorded_return(
        &self,
        syscall: &recordable::syscall::Syscall,
        again: Option<&Returned>,
    ) -> Option<Returned> {
        let mut returned = Returned { x0: 0, x1: 0, flags: 0 };
        for reg in &syscall.side_effects.as_ref().unwrap().registers {
            trace!("Setting X{:?} to 0x{:x}", reg.register, reg.value);
            let (name, value, recorded) = match reg.register {
                0x0 => ("0", again.map(|again| again.x0), &mut returned.x0),
                0x1 => ("1", again.map(|again| again.x1), &mut returned.x1),
                0x22 => {
                    returned.flags = reg.value;
                    continue;
                }
                _ => {
                    error!(
                        "Replay {}: unexpected register: {:?}",
                        self.state.event_idx, reg.register
                    );
                    return None;
                }
            };
            if let Some(value) = value.filter(|&value| value != reg.value) {
                error!(
                    "Replay {}: syscall return value {name} mismatch: expected 0x{:x}, got 0x{:x}",
                    self.state.event_idx, reg.value, value
                );
            }
            *recorded = reg.value;
        }
        Some(returned)
    }

    fn replay_side_effects(
        &mut self,
        t: &mut ThreadCx,
        syscall: &recordable::syscall::Syscall,
        num: u64,
        args: &[u64; 16],
        returned: &Returned,
    ) -> Result<()> {
        let side_effects = syscall.side_effects.as_ref().unwrap();
        self.replay_allocations(t, side_effects)?;
        self.apply_memory(t, &side_effects.memory);
        self.update_fd_table(num, args, returned.x0, returned.flags)?;
        self.state.event_idx += 1;
        Ok(())
    }

    /// Finishes replaying a syscall once appbox is done with it. Returns whether it was an event
    /// replayed (rather than e.g. one ending the guest).
    pub fn replay_syscall_done(&mut self, t: &mut ThreadCx, outcome: &Outcome) -> Result<bool> {
        let replayed = match self.in_syscall.take() {
            Some(InSyscall::Replayed) => true,
            Some(InSyscall::External {
                syscall,
                num,
                args,
                tpidrro,
            }) => match outcome {
                Outcome::Returned(again) => {
                    // appbox only knows about the main thread on replay, so keep the current
                    // thread's TSD base unless the syscall sets it.
                    if !(num == 0x8000_0000 && args[3] == 2) {
                        t.vcpu().set_sys_reg(av::SysReg::TPIDRRO_EL0, tpidrro)?;
                    }
                    let Some(returned) = self.recorded_return(&syscall, Some(again)) else {
                        anyhow::bail!("replay {}: unreplayable syscall", self.state.event_idx);
                    };
                    set_returned(t.vcpu(), &returned)?;
                    self.replay_side_effects(t, &syscall, num, &args, &returned)?;
                    true
                }
                _ => false,
            },
            Some(InSyscall::Recording { .. }) | None => false,
        };
        self.state.last_event_instructions = t.guest_instructions();
        Ok(replayed)
    }
}
