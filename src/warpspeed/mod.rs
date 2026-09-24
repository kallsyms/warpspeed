use anyhow::{Context, Result};
use appbox::hyperpom::error::{Error as HyperpomError, MemoryError};
use appbox::hyperpom::memory::VirtMemAllocator;
use appbox::loader::Loader;
use log::{debug, error, trace};
use std::collections::HashMap;

use appbox::applevisor as av;
use appbox::exec::ExecRequest;
use appbox::hyperpom::crash::ExitKind;
use appbox::vm::VmManager;
use appbox::syscalls;
use appbox::threads::{Registers, ThreadId, ThreadSwitch};
use appbox::trap::{
    explore_pointers, forward_syscall, read_syscall_context, write_syscall_result,
    DefaultTrapHandler, SyscallResult, TrapHandler,
};

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

/// Logs the guest's symbolicated stack, e.g. when it traps.
pub fn log_guest_stack(vm: &VmManager, loader: &Loader) {
    for (idx, addr) in appbox::unwind_user_stack(vm, 64).iter().enumerate() {
        match loader.symbolicate(*addr) {
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

#[derive(PartialEq)]
pub enum Mode {
    Record,
    Replay,
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
    exit_status: Option<i32>,
}

impl ReplayState {
    /// The index of the next event to record or replay.
    pub fn event_index(&self) -> usize {
        self.event_idx
    }
}

pub struct Warpspeed {
    pub trace: recordable::Trace,
    mode: Mode,
    state: ReplayState,
    trap_handler: DefaultTrapHandler,
    /// Replay only: events before this were already replayed once, so their writes to
    /// stdout/stderr aren't repeated.
    quiet_until: usize,
    /// Replay only: the guest memory the last event's recorded side effects wrote.
    event_writes: Vec<(u64, usize)>,
    shared_file_ids_by_identity: HashMap<(u64, u64), u64>,
    shared_files_by_id: HashMap<u64, recordable::trace::SharedFile>,
    shadow_files: HashMap<u64, ShadowFile>,
}

impl Warpspeed {
    pub fn new(trace: recordable::Trace, mode: Mode) -> Result<Self> {
        anyhow::ensure!(
            appbox::threading::model() == appbox::threading::ThreadingModel::TimeShared,
            "recording and replaying need the guest's threads time-shared, not in parallel"
        );
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

        let mut trap_handler = DefaultTrapHandler::new()?;
        if mode == Mode::Replay {
            // Thread switches come from the recording.
            trap_handler.set_quantum(None);
        }
        Ok(Self {
            trace,
            mode,
            state: ReplayState {
                event_idx: 0,
                current_tid: 0,
                last_event_instructions: 0,
                pending: HashMap::new(),
                fd_table: HashMap::new(),
                exit_status: None,
            },
            trap_handler,
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

        // And finally, exit() so appbox returns out ExitKind::Exit.
        if num == syscalls::SYS_exit {
            return true;
        }

        // XXX: kinda hack. platform syscalls dealing with TSD are replayed so appbox's TSD management handles things correctly later
        num == 0x8000_0000
    }

    /// Records the changes appbox made to guest memory itself.
    fn record_guest_memory_changes(
        &mut self,
        vma: &VirtMemAllocator,
        side_effects: &mut recordable::SideEffects,
    ) -> Result<()> {
        let changes = self.trap_handler.take_guest_memory_changes();
        for (address, size) in changes.allocations {
            side_effects
                .allocations
                .push(side_effects::Allocation { address, size });
        }
        for (address, len) in changes.writes {
            let mut value = vec![0; len as usize];
            vma.read(address, &mut value)?;
            side_effects.memory.push(side_effects::Memory { address, value });
        }
        Ok(())
    }

    /// Repeats appbox's allocations on the guest's behalf, which must land where they did.
    fn replay_allocations(
        &mut self,
        vma: &mut VirtMemAllocator,
        side_effects: &recordable::SideEffects,
    ) -> Result<()> {
        for allocation in &side_effects.allocations {
            let address = self
                .trap_handler
                .allocate_guest_memory(vma, allocation.size)?;
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

    /// Records a syscall `tid` left the vCPU in, and the switch to the next thread.
    #[allow(clippy::too_many_arguments)]
    fn record_switch(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &VirtMemAllocator,
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
        self.record_guest_memory_changes(vma, &mut side_effects)?;
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
        self.record_switch_in(vcpu, vma, tid, switch)
    }

    /// Records the switch from `tid` to the thread now on the vCPU.
    fn record_switch_in(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &VirtMemAllocator,
        tid: ThreadId,
        switch: ThreadSwitch,
    ) -> Result<()> {
        let registers = Registers::save(vcpu)?;
        let memory = match self.state.pending.remove(&switch.to) {
            Some(pending) => {
                self.complete_pending(&pending, &registers)?;
                diff_pages(vma, pending.before_pages)?
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

    /// Replays a syscall the current thread left the vCPU in, and the switch to the next thread.
    fn replay_switch(
        &mut self,
        vm: &mut VmManager,
        num: u64,
        args: &[u64; 16],
        syscall: &recordable::syscall::Syscall,
    ) -> Result<ExitKind> {
        let side_effects = syscall.side_effects.as_ref().unwrap();
        if side_effects.external && !self.already_written(num, args) {
            // Only plain forwarded syscalls can block, so there's nothing for appbox to do.
            self.prepare_replay_external_syscall(num, args, syscall)?;
            forward_syscall(num, args);
        }
        self.replay_allocations(&mut vm.vma(), side_effects)?;
        self.apply_memory(&mut vm.vma(), &side_effects.memory);
        self.state.pending.insert(
            self.state.current_tid,
            PendingSyscall {
                num,
                args: *args,
                before_pages: HashMap::new(),
            },
        );
        self.state.event_idx += 1;
        self.replay_switch_in(vm)
    }

    /// Replays the switch to another thread that the next event records.
    fn replay_switch_in(
        &mut self,
        vm: &mut VmManager,
    ) -> Result<ExitKind> {
        let Some(event) = self.trace.events.get(self.state.event_idx) else {
            error!("Replay {}: trace ended mid thread switch", self.state.event_idx);
            return Ok(ExitKind::Exit);
        };
        let Some(recordable::log_event::Event::Scheduling(scheduling::Scheduling {
            event: Some(scheduling::scheduling::Event::Switch(switch)),
            ..
        })) = &event.event
        else {
            error!(
                "Replay {}: expected a thread switch, got {:?}",
                self.state.event_idx, event.event
            );
            return Ok(ExitKind::Exit);
        };
        let switch = switch.clone();
        let registers = registers_from_proto(
            switch
                .registers
                .as_ref()
                .context("thread switch without registers")?,
        )?;
        registers.restore(&vm.vcpu)?;
        self.apply_memory(&mut vm.vma(), &switch.memory);
        if let Some(pending) = self.state.pending.remove(&switch.new_tid) {
            self.complete_pending(&pending, &registers)?;
        }
        trace!("Replay {}: switched to thread {}", self.state.event_idx, switch.new_tid);
        self.state.current_tid = switch.new_tid;
        self.state.event_idx += 1;
        Ok(ExitKind::Continue)
    }

    /// Handles the current thread's time slice running out (`VmRunResult::Timer`) while recording:
    /// if appbox preempts it for another thread, records where, and the switch.
    pub fn handle_timer(&mut self, vm: &mut VmManager) -> Result<()> {
        if self.mode == Mode::Replay {
            return Ok(());
        }
        let tid = self.trap_handler.current_thread();
        let instructions = vm.guest_instructions() - self.state.last_event_instructions;
        let preempted = Registers::save(&vm.vcpu)?;
        let Some(switch) = self.trap_handler.handle_timer(vm)? else {
            return Ok(());
        };
        let mut side_effects = recordable::SideEffects::default();
        self.record_guest_memory_changes(&vm.vma(), &mut side_effects)?;
        self.trace.events.push(recordable::LogEvent {
            pc: preempted.pc,
            register_state: vec![],
            tid,
            event: Some(recordable::log_event::Event::Preemption(
                recordable::Preemption {
                    instructions,
                    registers: Some(registers_to_proto(&preempted)),
                    side_effects: Some(side_effects),
                },
            )),
        });
        self.state.event_idx += 1;
        self.record_switch_in(&vm.vcpu, &vm.vma(), tid, switch)?;
        self.state.last_event_instructions = vm.guest_instructions();
        Ok(())
    }

    /// The current thread's next preemption, if replay's next event is one: how many guest
    /// instructions after the previous event (as counted when recording), and where.
    pub fn next_preemption(&self) -> Option<(u64, Registers)> {
        if self.mode != Mode::Replay {
            return None;
        }
        let event = self.trace.events.get(self.state.event_idx)?;
        let Some(recordable::log_event::Event::Preemption(preemption)) = &event.event else {
            return None;
        };
        let registers = registers_from_proto(preemption.registers.as_ref()?).ok()?;
        (event.tid == self.state.current_tid).then_some((preemption.instructions, registers))
    }

    /// Replays the next event, a preemption, once the guest is where it was preempted: the
    /// switch to the next thread.
    pub fn apply_preemption(&mut self, vm: &mut VmManager) -> Result<ExitKind> {
        let event = self.trace.events[self.state.event_idx].clone();
        let Some(recordable::log_event::Event::Preemption(preemption)) = event.event else {
            anyhow::bail!("replay {}: not a preemption", self.state.event_idx);
        };
        self.event_writes.clear();
        if let Some(side_effects) = &preemption.side_effects {
            self.replay_allocations(&mut vm.vma(), side_effects)?;
            self.apply_memory(&mut vm.vma(), &side_effects.memory);
        }
        self.state.event_idx += 1;
        let exit = self.replay_switch_in(vm)?;
        self.state.last_event_instructions = vm.guest_instructions();
        Ok(exit)
    }

    /// Where replay is (see [`ReplayState`]).
    pub fn state(&self) -> ReplayState {
        self.state.clone()
    }

    /// Puts replay back to `state`, as of a checkpoint that `vm` was just restored to.
    pub fn set_state(&mut self, state: ReplayState, vm: &VmManager) {
        self.state = state;
        self.state.last_event_instructions = vm.guest_instructions();
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

    /// The status the guest exited with, once it has.
    pub fn exit_status(&self) -> Option<i32> {
        self.state.exit_status
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

    /// See [`DefaultTrapHandler::checkpoint`].
    pub fn checkpoint(&mut self, vm: &mut VmManager) -> Result<appbox::checkpoint::Checkpoint> {
        self.trap_handler.checkpoint(vm)
    }

    /// See [`DefaultTrapHandler::restore`].
    pub fn restore_checkpoint(
        &mut self,
        vm: &mut VmManager,
        checkpoint: &appbox::checkpoint::Checkpoint,
    ) -> Result<()> {
        self.trap_handler.restore(vm, checkpoint)
    }

    /// See [`DefaultTrapHandler::discard_checkpoint`].
    pub fn discard_checkpoint(
        &mut self,
        vm: &mut VmManager,
        checkpoint: &appbox::checkpoint::Checkpoint,
    ) -> Result<()> {
        self.trap_handler.discard_checkpoint(vm, checkpoint)
    }

    /// Applies recorded writes to guest memory, telling checkpoints first.
    fn apply_memory(&mut self, vma: &mut VirtMemAllocator, memory: &[side_effects::Memory]) {
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

    /// Replaces the guest's image as `request` says, like the kernel's exec.
    pub fn exec(
        &mut self,
        vm: VmManager,
        loader: Loader,
        request: &ExecRequest,
    ) -> Result<(VmManager, Loader)> {
        let (mut vm, loader) = appbox::exec::exec(vm, loader, &mut self.trap_handler, request)?;
        vm.count_instructions()?;
        self.state.last_event_instructions = vm.guest_instructions();
        // Only the calling thread survives, and close-on-exec descriptors are gone.
        self.state.pending.clear();
        self.state.fd_table
            .retain(|&fd, _| unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0);
        Ok((vm, loader))
    }

    /// Handles a syscall (`VmRunResult::Svc`), recording or replaying it.
    pub fn trap_handler(&mut self, vm: &mut VmManager, loader: &Loader) -> Result<ExitKind> {
        let exit = self.handle_syscall(vm, loader);
        self.state.last_event_instructions = vm.guest_instructions();
        exit
    }

    fn handle_syscall(&mut self, vm: &mut VmManager, loader: &Loader) -> Result<ExitKind> {
        let ctx = read_syscall_context(&mut vm.vcpu)?;
        let elr = ctx.elr;
        trace!("ELR_EL1: {:#x}", elr);
        if ctx.esr != 0x56000080 {
            error!("Fault!");
            error!("{}", vm.vcpu);
            return Ok(ExitKind::Crash("Unhandled fault".to_string()));
        }

        let num = ctx.num;
        let args = ctx.args;
        debug!(
            "{}: Incoming syscall ({}) {:x}(x{:x?})",
            self.state.event_idx,
            syscalls::syscall_name(num).unwrap_or("<unknown>"),
            num,
            args
        );

        let mut ret0: u64 = 0;
        let mut ret1: u64 = 0;
        let mut cflags: u64 = 0;
        let mut exit_kind = ExitKind::Continue;
        let mut side_effects = recordable::SideEffects::default();
        let mut shared_map = None;
        let tid;
        // Stage 2: do the syscall.
        // If recording:
        //   1. Snapshot "reachable" memory before the syscall
        //   2. Perform the syscall
        //   3. Diff previously stored reachable pages now that the syscall is done, recording what memory changed.
        //      If the thread left the vCPU instead, that happens when it's switched back to.
        // If replaying, make sure we're in the correct place and simply apply the side effects.
        match self.mode {
            Mode::Record => {
                tid = self.trap_handler.current_thread();
                let before_pages = snapshot_pages(&vm.vma(), &args)?;

                let res = self.trap_handler.handle_syscall(&ctx, vm, loader)?;
                exit_kind = res.exit.clone();
                if let ExitKind::Exec(request) = &exit_kind {
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
                    return Ok(exit_kind);
                }
                if exit_kind != ExitKind::Continue && exit_kind != ExitKind::Exit {
                    return Ok(exit_kind);
                }
                if let Some(switch) = res.thread_switch {
                    self.record_switch(&vm.vcpu, &vm.vma(), elr, num, &args, tid, before_pages, switch)?;
                    return Ok(ExitKind::Continue);
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
                        vm.vma().read(buf, &mut data)?;
                        side_effects.memory.push(recordable::side_effects::Memory {
                            address: buf,
                            value: data,
                        });
                    }
                    _ => side_effects.memory.extend(diff_pages(&vm.vma(), before_pages)?),
                }
                self.record_guest_memory_changes(&vm.vma(), &mut side_effects)?;

                trace!(
                    "Changed mem: {:?}",
                    side_effects
                        .memory
                        .iter()
                        .map(|m| (m.address, m.address + m.value.len() as u64))
                        .collect::<Vec<_>>()
                );
                shared_map = self.record_shared_map(num, &args, cflags)?;
            }
            Mode::Replay => {
                tid = self.state.current_tid;
                self.event_writes.clear();
                if num == syscalls::SYS_exit {
                    self.state.exit_status = Some(args[0] as i32);
                }
                let Some(event) = self.trace.events.get(self.state.event_idx) else {
                    error!("Replay {}: past the end of the recording", self.state.event_idx);
                    return Ok(ExitKind::Exit);
                };
                if elr != event.pc {
                    error!(
                        "Replay {}: pc mismatch: expected 0x{:x}, got 0x{:x}",
                        self.state.event_idx, event.pc, elr
                    );
                    return Ok(ExitKind::Exit);
                }
                if tid != event.tid {
                    error!(
                        "Replay {}: thread mismatch: expected {}, got {}",
                        self.state.event_idx, event.tid, tid
                    );
                    return Ok(ExitKind::Exit);
                }

                match &event.event {
                    Some(recordable::log_event::Event::Exec(exec)) => {
                        let request = ExecRequest {
                            path: exec.path.clone().into(),
                            argv: exec.argv.clone(),
                            envp: exec.envp.clone(),
                        };
                        self.state.event_idx += 1;
                        return Ok(ExitKind::Exec(request));
                    }
                    Some(crate::recordable::log_event::Event::Syscall(syscall)) => {
                        let syscall = syscall.clone();
                        if num != syscall.syscall_number {
                            error!(
                                "Replay {}: syscall mismatch: expected 0x{:x}, got 0x{:x}",
                                self.state.event_idx, syscall.syscall_number, num
                            );
                        }
                        if syscall.descheduled {
                            return self.replay_switch(vm, num, &args, &syscall);
                        }

                        let side_effects_ref = syscall.side_effects.as_ref().unwrap();
                        let mut res: Option<SyscallResult> = None;

                        if side_effects_ref.external && !self.already_written(num, &args) {
                            self.prepare_replay_external_syscall(num, &args, &syscall)?;
                            trace!("Replay syscall index {}", self.state.event_idx);
                            // appbox only knows about the main thread on replay, so keep the
                            // current thread's TSD base unless the syscall sets it.
                            let tpidrro = vm.vcpu.get_sys_reg(av::SysReg::TPIDRRO_EL0)?;
                            let handler_res =
                                self.trap_handler.handle_syscall(&ctx, vm, loader)?;
                            if !(num == 0x8000_0000 && args[3] == 2) {
                                vm.vcpu.set_sys_reg(av::SysReg::TPIDRRO_EL0, tpidrro)?;
                            }
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
                                                    self.state.event_idx, reg.value, handler_res.ret0
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
                                                    self.state.event_idx, reg.value, handler_res.ret1
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
                                        self.state.event_idx, reg.register
                                    );
                                    return Ok(ExitKind::Exit);
                                }
                            }
                        }
                        self.replay_allocations(&mut vm.vma(), side_effects_ref)?;
                        self.apply_memory(&mut vm.vma(), &side_effects_ref.memory);
                    }
                    _ => {
                        error!(
                            "replay {}: unexpected event type: {:?}",
                            self.state.event_idx, event.event
                        );
                        return Ok(ExitKind::Exit);
                    }
                }
            }
        }

        // Stage 3: now that we've done the syscall, record the final state as side effects.
        let cpsr = (vm.vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | cflags;

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
            // The process ending (e.g. with its last thread) must happen on replay too.
            side_effects.external = self.is_external(num, &args) || exit_kind == ExitKind::Exit;

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
        }

        self.update_fd_table(num, &args, ret0, cflags)?;
        self.state.event_idx += 1;

        if exit_kind != ExitKind::Continue {
            return Ok(exit_kind);
        }

        debug!("Returning x0={:x} x1={:x} cpsr={:x}", ret0, ret1, cpsr);
        write_syscall_result(&mut vm.vcpu, elr, ret0, ret1, cflags)?;
        Ok(ExitKind::Continue)
    }
}
