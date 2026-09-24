//! Replaying a recording, forwards and backwards, under a debugger's control.
//!
//! Going backwards restores checkpoints (see `appbox::checkpoint`), which replay takes as it goes
//! (and thins out, keeping more of the recent ones), and replays forwards from there.
//! Reverse-continue scans forwards from the latest checkpoint before where replay is, noting the
//! debugger's breakpoint and watchpoint hits on the way, then goes back and lands on the last of
//! them; if there were none, it tries the checkpoint before, and so on. Reverse-step replays to
//! shortly before where replay is and single-steps the rest of the way, noting the state before
//! it, then replays to that; the first instruction after an event steps back to before the event
//! (its svc, or where its thread was preempted).
//!
//! Positions in the replay (where the debugger stopped, or where a thread was preempted) are
//! found like preemptions: timed runs of the guest, by its approximate instruction count, to
//! short of the position, then a hardware breakpoint on its pc until the registers match. A
//! debugger hit is exact: the nth hit of that breakpoint or watchpoint since an event.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use appbox::applevisor as av;
use appbox::hyperpom::crash::ExitKind;
use appbox::loader::Loader;
use appbox::threads::Registers;
use appbox::vm::{VmManager, VmRunResult, WatchKind, Watchpoint};
use log::{debug, info, warn};

use crate::recordable::Trace;
use crate::warpspeed::{Mode, ReplayState, Warpspeed};

/// How far short of a position's instruction count to stop timing the guest and start looking
/// for its registers at a breakpoint. It must cover how much host interrupts inflated the count
/// (seen up to ~100k in a ~3ms slice).
const POSITION_MARGIN: u64 = 150_000;
/// Faster than any Apple core retires instructions (8 per cycle at ~3.2GHz), so a timed run sized
/// assuming it can't overshoot. Measuring the rate instead isn't safe: a run in which the host
/// descheduled the vCPU's thread measures slow.
const MAX_INSTRUCTIONS_PER_NS: f64 = 26.0;
/// The shortest timed run worth doing before switching to breakpoints.
const MIN_TIMER_NS: f64 = 2_000.0;
/// How far past a position the breakpoint phase could be, given the instruction counts, before
/// concluding it was missed: covers host interrupts inflating the counts.
const MISSED_SLACK: u64 = 500_000;
/// Guest instructions between checkpoints.
const CHECKPOINT_EVERY: u64 = 50_000_000;
/// Hardware breakpoint slot finding positions uses; the debugger's use the rest.
const POSITION_SLOT: usize = 0;

/// Why replay stopped, to tell the debugger.
#[derive(Clone, Debug)]
pub enum Stop {
    /// At one of the debugger's breakpoints.
    Breakpoint,
    /// After a single step.
    Step,
    /// After an access to `addr`, watched by a `kind` watchpoint.
    Watchpoint { kind: WatchKind, addr: u64 },
    /// Went backwards to the start of the recording (or, after an exec, of the new image).
    Start,
    /// The guest exited (or crashed), with this status.
    Exited(ExitKind, Option<i32>),
}

/// A point in the replay: `instructions` guest instructions (as counted: an upper bound) after
/// event `event` (i.e. before it's replayed), with the current thread's `registers`.
#[derive(Clone, Debug)]
struct Position {
    event: usize,
    instructions: u64,
    registers: Registers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum HitKind {
    Breakpoint(u64),
    Watchpoint(Watchpoint),
}

/// A hit of one of the debugger's breakpoints or watchpoints: the `nth` hit of `kind` since
/// event `event`. For a watchpoint, `addr` is the address accessed.
#[derive(Clone, Debug)]
struct Hit {
    event: usize,
    kind: HitKind,
    nth: u64,
    addr: u64,
    /// The state when stopped for it.
    registers: Registers,
}

impl Hit {
    fn stop(&self) -> Stop {
        match self.kind {
            HitKind::Breakpoint(_) => Stop::Breakpoint,
            HitKind::Watchpoint(watchpoint) => Stop::Watchpoint {
                kind: watchpoint.kind,
                addr: self.addr,
            },
        }
    }
}

struct Checkpoint {
    appbox: appbox::checkpoint::Checkpoint,
    state: ReplayState,
    registers: Registers,
    /// Checkpoints taken before, to judge its age when thinning them out.
    sequence: u64,
}

impl Checkpoint {
    fn position(&self) -> Position {
        Position {
            event: self.state_event(),
            instructions: 0,
            registers: self.registers.clone(),
        }
    }

    fn state_event(&self) -> usize {
        self.state.event_index()
    }
}

/// What to run the guest towards.
enum Goal<'a> {
    /// The debugger's next breakpoint or watchpoint hit, or the end.
    Debugger,
    /// After one instruction.
    Step,
    /// `to`, silently, collecting the debugger's hits before it.
    Scan { to: &'a Position, hits: &'a mut Vec<Hit> },
    /// That hit, silently.
    Land(&'a Hit),
    /// The start of that event, silently.
    ToEvent(usize),
}

enum Outcome {
    Stopped(Stop),
    /// Got to the scan's position.
    Reached,
    /// Ran past where the thread was preempted at this event while recording.
    Missed(usize),
}

/// What running the guest for a while came to.
enum GuestEvent {
    /// Got to the position looked for.
    AtPosition,
    /// It's making a syscall.
    Syscall,
    /// At one of the debugger's breakpoints (before the instruction), or after an access
    /// watched by one of its watchpoints.
    Hit(HitKind, u64),
    /// Passed the position looked for.
    Missed,
    /// Executed the one instruction it was asked to.
    Stepped,
    Other(VmRunResult),
}

/// What stepping to a position found before it.
enum Trail {
    /// The state before it. The instruction count is the position's, as the count drifts while
    /// stepping.
    Before(Position),
    /// Nothing: it's the first state of its event.
    First,
    /// It was passed, so the count led the coarse phase astray.
    Passed,
}

fn same_point(a: &Registers, b: &Registers) -> bool {
    a.pc == b.pc && a.sp == b.sp && a.x == b.x && a.q == b.q && a.cpsr >> 28 == b.cpsr >> 28
}

pub struct Replayer {
    vm: Option<VmManager>,
    loader: Option<Loader>,
    warpspeed: Warpspeed,
    breakpoints: Vec<u64>,
    watchpoints: Vec<Watchpoint>,
    /// Oldest first; the first is where replay (or the current image) started.
    checkpoints: Vec<Checkpoint>,
    next_sequence: u64,
    instructions_at_checkpoint: u64,
    checkpoint_every: u64,
    /// Preemptions (by event) to find without timing the guest first: slow, but can't overshoot.
    careful: BTreeSet<usize>,
    /// How fast the guest is assumed to run at most, when timing it. Only lowered for testing.
    max_instructions_per_ns: f64,
    /// The furthest event replayed so far.
    high_water: usize,
    /// Hits by kind since event `hit_counts_event`.
    hit_counts: HashMap<HitKind, u64>,
    hit_counts_event: usize,
    /// Hits before this event were already reported to the debugger.
    report_hits_from: usize,
    /// Stopped at this breakpoint, which must be stepped over before going on.
    at_breakpoint: Option<u64>,
    finished: Option<ExitKind>,
}

impl Replayer {
    pub fn new(trace: Trace) -> Result<Self> {
        let target = trace.target.clone().context("trace missing target")?;
        let mut vm = VmManager::new()?;
        let loader = appbox::loader::load_macho(
            &mut vm,
            &PathBuf::from(&target.path),
            target.arguments,
            target.environment,
        )?;
        vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
        vm.vcpu
            .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;
        vm.count_instructions()?;
        let mut replayer = Self {
            vm: Some(vm),
            loader: Some(loader),
            warpspeed: Warpspeed::new(trace, Mode::Replay)?,
            breakpoints: Vec::new(),
            watchpoints: Vec::new(),
            checkpoints: Vec::new(),
            next_sequence: 0,
            instructions_at_checkpoint: 0,
            checkpoint_every: std::env::var("WARPSPEED_CHECKPOINT_EVERY")
                .ok()
                .and_then(|every| every.parse().ok())
                .unwrap_or(CHECKPOINT_EVERY),
            careful: BTreeSet::new(),
            max_instructions_per_ns: MAX_INSTRUCTIONS_PER_NS,
            high_water: 0,
            hit_counts: HashMap::new(),
            hit_counts_event: 0,
            report_hits_from: 0,
            at_breakpoint: None,
            finished: None,
        };
        replayer.take_checkpoint()?;
        Ok(replayer)
    }

    /// For testing recovering from overshooting a preemption: assume the guest runs no faster
    /// than this until the first miss.
    pub fn assume_max_instructions_per_ns(&mut self, rate: f64) {
        self.max_instructions_per_ns = rate;
    }

    pub fn vm(&mut self) -> &mut VmManager {
        self.vm.as_mut().expect("a VM")
    }

    fn vm_ref(&self) -> &VmManager {
        self.vm.as_ref().expect("a VM")
    }

    /// Sets or clears a debugger breakpoint at `addr`, as a hardware breakpoint.
    pub fn set_breakpoint(&mut self, addr: u64, set: bool) -> Result<()> {
        if set {
            if !self.breakpoints.contains(&addr) {
                self.breakpoints.push(addr);
            }
        } else {
            self.breakpoints.retain(|&a| a != addr);
        }
        self.arm_debugger_breakpoints()
    }

    fn arm_debugger_breakpoints(&mut self) -> Result<()> {
        let slots = self.vm_ref().breakpoint_slots()?;
        anyhow::ensure!(
            self.breakpoints.len() < slots,
            "only {} hardware breakpoints",
            slots - 1
        );
        for slot in 1..slots {
            let addr = self.breakpoints.get(slot - 1).copied();
            self.vm().set_hardware_breakpoint_slot(slot, addr)?;
        }
        Ok(())
    }

    /// Takes the debugger's breakpoints and watchpoints out of the VM, or puts them back.
    fn arm_debugger(&mut self, armed: bool) -> Result<()> {
        if armed {
            self.arm_debugger_breakpoints()?;
        } else {
            for slot in 1..self.vm_ref().breakpoint_slots()? {
                self.vm().set_hardware_breakpoint_slot(slot, None)?;
            }
        }
        for slot in 0..self.vm_ref().watchpoint_slots()? {
            let watchpoint = self.watchpoints.get(slot).copied().filter(|_| armed);
            self.vm().set_hardware_watchpoint(slot, watchpoint)?;
        }
        Ok(())
    }

    /// Sets or clears a debugger watchpoint, as a hardware watchpoint.
    pub fn set_watchpoint(&mut self, watchpoint: Watchpoint, set: bool) -> Result<()> {
        if set {
            if !self.watchpoints.contains(&watchpoint) {
                self.watchpoints.push(watchpoint);
            }
        } else {
            self.watchpoints.retain(|w| *w != watchpoint);
        }
        let slots = self.vm_ref().watchpoint_slots()?;
        if self.watchpoints.len() > slots {
            self.watchpoints.pop();
            anyhow::bail!("only {slots} hardware watchpoints");
        }
        for slot in 0..slots {
            let watchpoint = self.watchpoints.get(slot).copied();
            if let Err(err) = self.vm().set_hardware_watchpoint(slot, watchpoint) {
                self.watchpoints.retain(|w| Some(*w) != watchpoint);
                return Err(err);
            }
        }
        Ok(())
    }

    /// Replays until the debugger's next breakpoint or watchpoint hit, or the end.
    pub fn cont(&mut self) -> Result<Stop> {
        self.leave_breakpoint()?;
        self.run_recovering(|replayer| replayer.run(Goal::Debugger))
    }

    /// Replays one instruction.
    pub fn step(&mut self) -> Result<Stop> {
        self.leave_breakpoint()?;
        self.run_recovering(|replayer| replayer.run(Goal::Step))
    }

    /// Resuming at one of the debugger's breakpoints runs its instruction rather than stopping
    /// for it again, however replay got there.
    fn leave_breakpoint(&mut self) -> Result<()> {
        let pc = self.vm_ref().vcpu.get_reg(av::Reg::PC)?;
        if self.breakpoints.contains(&pc) {
            self.at_breakpoint = Some(pc);
        }
        Ok(())
    }

    /// Replays to the end, without a debugger.
    pub fn run_to_end(&mut self) -> Result<Stop> {
        loop {
            match self.cont()? {
                stop @ Stop::Exited(..) => return Ok(stop),
                _ => continue,
            }
        }
    }

    /// Runs forwards with `run`, recovering from missing a preemption (by going back to a
    /// checkpoint and finding it carefully) and carrying on.
    fn run_recovering(&mut self, run: impl Fn(&mut Self) -> Result<Outcome>) -> Result<Stop> {
        loop {
            match run(self)? {
                Outcome::Stopped(stop) => return Ok(stop),
                Outcome::Reached => unreachable!("only scans reach positions"),
                Outcome::Missed(event) => {
                    info!("Restarting replay to find the preemption at event {event} carefully");
                    self.careful.insert(event);
                    self.max_instructions_per_ns = MAX_INSTRUCTIONS_PER_NS;
                    // What's been replayed up to it was already reported.
                    self.report_hits_from = self.report_hits_from.max(event + 1);
                    let index = self
                        .checkpoints
                        .iter()
                        .rposition(|checkpoint| checkpoint.state_event() <= event)
                        .unwrap_or(0);
                    self.restore(index)?;
                }
            }
        }
    }

    /// Replays backwards to the debugger's previous breakpoint or watchpoint hit, or the start.
    pub fn reverse_cont(&mut self) -> Result<Stop> {
        let mut end = self.position()?;
        // The latest checkpoint before where replay is.
        let mut index = self
            .checkpoints
            .iter()
            .rposition(|checkpoint| {
                checkpoint.state_event() < end.event
                    || (checkpoint.state_event() == end.event
                        && !same_point(&checkpoint.registers, &end.registers))
            })
            .unwrap_or(0);
        loop {
            self.restore(index)?;
            let mut hits = Vec::new();
            match self.run(Goal::Scan {
                to: &end,
                hits: &mut hits,
            })? {
                Outcome::Reached | Outcome::Stopped(Stop::Exited(..)) => {}
                Outcome::Missed(event) => {
                    self.careful.insert(event);
                    continue;
                }
                Outcome::Stopped(stop) => unreachable!("scans don't stop for {stop:?}"),
            }

            if let Some(last) = hits.pop() {
                debug!("reverse-continue: landing on {last:?}");
                loop {
                    self.restore(index)?;
                    match self.run(Goal::Land(&last))? {
                        Outcome::Stopped(stop) => return Ok(stop),
                        Outcome::Missed(event) => {
                            self.careful.insert(event);
                        }
                        Outcome::Reached => unreachable!("landing doesn't reach positions"),
                    }
                }
            }
            if index == 0 {
                self.restore(0)?;
                return Ok(Stop::Start);
            }
            end = self.checkpoints[index].position();
            index -= 1;
        }
    }

    /// Replays backwards by one instruction: to the state the guest was in before the current
    /// one, which is found by stepping forwards to here from shortly before.
    pub fn reverse_step(&mut self) -> Result<Stop> {
        let target = self.position()?;
        self.arm_debugger(false)?;
        let stop = self.go_before(&target).or_else(|err| {
            warn!("couldn't step backwards, staying put: {err:#}");
            self.replay_to(&target).map(|()| Stop::Step)
        });
        self.arm_debugger(true)?;
        stop
    }

    fn go_before(&mut self, target: &Position) -> Result<Stop> {
        loop {
            self.replay_to_event(target.event)?;
            match self.trail(target)? {
                Trail::Before(previous) => {
                    self.replay_to(&previous)?;
                    return Ok(Stop::Step);
                }
                Trail::First => break,
                Trail::Passed if self.careful.contains(&target.event) => {
                    anyhow::bail!("stepping to {target:?} passed it")
                }
                Trail::Passed => {
                    self.careful.insert(target.event);
                }
            }
        }

        // It's the first instruction since the previous event, so go to just before that.
        if target.event == self.checkpoints[0].state_event() {
            self.restore(0)?;
            return Ok(Stop::Start);
        }
        let event = target.event - 1;
        self.replay_to_event(event)?;
        if let Some((instructions, registers)) = self.warpspeed.next_preemption() {
            self.replay_to(&Position {
                event,
                instructions,
                registers,
            })?;
            return Ok(Stop::Step);
        }
        match self.run_guest(None)? {
            GuestEvent::Syscall => {}
            _ => anyhow::bail!("replaying event {event} didn't end in its syscall"),
        }
        // Back out of the exception, to before the svc.
        let vcpu = &self.vm_ref().vcpu;
        let mut registers = Registers::save_at_syscall(vcpu)?;
        registers.pc -= 4;
        registers.restore(vcpu)?;
        Ok(Stop::Step)
    }

    /// From the start of `target`'s event, runs to shortly before it, then steps to it, to find
    /// the state before it.
    fn trail(&mut self, target: &Position) -> Result<Trail> {
        if self.run_coarse(target)?.is_some() {
            return Ok(Trail::Passed);
        }
        let mut previous = None;
        loop {
            let registers = Registers::save(&self.vm_ref().vcpu)?;
            if same_point(&registers, &target.registers) {
                return Ok(previous.map_or(Trail::First, Trail::Before));
            }
            previous = Some(Position {
                event: target.event,
                instructions: target.instructions,
                registers,
            });
            match self.single_step()? {
                GuestEvent::Stepped | GuestEvent::Other(VmRunResult::Timer) => {}
                _ => return Ok(Trail::Passed),
            }
        }
    }

    /// Replays silently from the latest checkpoint before event `event` to its start.
    fn replay_to_event(&mut self, event: usize) -> Result<()> {
        loop {
            self.restore(self.checkpoint_before(event))?;
            match self.run(Goal::ToEvent(event))? {
                Outcome::Reached => return Ok(()),
                Outcome::Missed(missed) => {
                    self.careful.insert(missed);
                }
                Outcome::Stopped(stop) => anyhow::bail!("replaying to event {event}: {stop:?}"),
            }
        }
    }

    /// Replays silently from the latest checkpoint before `position` to it.
    fn replay_to(&mut self, position: &Position) -> Result<()> {
        loop {
            self.restore(self.checkpoint_before(position.event))?;
            match self.run(Goal::Scan {
                to: position,
                hits: &mut Vec::new(),
            })? {
                Outcome::Reached => return Ok(()),
                Outcome::Missed(missed) => {
                    self.careful.insert(missed);
                }
                Outcome::Stopped(stop) => anyhow::bail!("replaying to {position:?}: {stop:?}"),
            }
        }
    }

    /// The latest checkpoint at or before the start of event `event`.
    fn checkpoint_before(&self, event: usize) -> usize {
        self.checkpoints
            .iter()
            .rposition(|checkpoint| checkpoint.state_event() <= event)
            .unwrap_or(0)
    }

    fn position(&self) -> Result<Position> {
        let vm = self.vm_ref();
        Ok(Position {
            event: self.warpspeed.event_index(),
            instructions: vm.guest_instructions() - self.warpspeed.last_event_instructions(),
            registers: Registers::save(&vm.vcpu)?,
        })
    }

    fn take_checkpoint(&mut self) -> Result<()> {
        let vm = self.vm.as_mut().expect("a VM");
        let appbox = self.warpspeed.checkpoint(vm)?;
        let registers = Registers::save(&vm.vcpu)?;
        self.instructions_at_checkpoint = vm.guest_instructions();
        self.checkpoints.push(Checkpoint {
            appbox,
            state: self.warpspeed.state(),
            registers,
            sequence: self.next_sequence,
        });
        self.next_sequence += 1;
        self.thin_checkpoints()
    }

    /// Keeps at most two checkpoints of each power-of-two age (in checkpoints taken since), and
    /// always the first.
    fn thin_checkpoints(&mut self) -> Result<()> {
        let newest = self.next_sequence - 1;
        let mut per_age: HashMap<u32, usize> = HashMap::new();
        let mut index = self.checkpoints.len();
        while index > 1 {
            index -= 1;
            let age = newest - self.checkpoints[index].sequence;
            let bucket = u64::BITS - age.leading_zeros();
            let count = per_age.entry(bucket).or_default();
            *count += 1;
            if *count > 2 {
                let checkpoint = self.checkpoints.remove(index);
                let vm = self.vm.as_mut().expect("a VM");
                self.warpspeed.discard_checkpoint(vm, &checkpoint.appbox)?;
            }
        }
        debug!(
            "{} checkpoints, {} MiB saved",
            self.checkpoints.len(),
            self.vm_ref().checkpointed_bytes() >> 20
        );
        Ok(())
    }

    /// Goes back to checkpoint `index`, discarding later ones.
    fn restore(&mut self, index: usize) -> Result<()> {
        self.checkpoints.truncate(index + 1);
        let checkpoint = &self.checkpoints[index];
        let vm = self.vm.as_mut().expect("a VM");
        self.warpspeed.restore_checkpoint(vm, &checkpoint.appbox)?;
        self.warpspeed.set_state(checkpoint.state.clone(), vm);
        self.warpspeed.set_quiet_until(self.high_water);
        self.instructions_at_checkpoint = vm.guest_instructions();
        self.hit_counts.clear();
        self.hit_counts_event = self.warpspeed.event_index();
        self.at_breakpoint = None;
        self.finished = None;
        Ok(())
    }

    /// Counts a hit of `kind` at the current event.
    fn count_hit(&mut self, kind: HitKind, addr: u64) -> Result<Hit> {
        let event = self.warpspeed.event_index();
        if self.hit_counts_event != event {
            self.hit_counts.clear();
            self.hit_counts_event = event;
        }
        let nth = self.hit_counts.entry(kind).or_default();
        *nth += 1;
        Ok(Hit {
            event,
            kind,
            nth: *nth,
            addr,
            registers: Registers::save(&self.vm_ref().vcpu)?,
        })
    }

    fn run(&mut self, mut goal: Goal) -> Result<Outcome> {
        loop {
            if let Some(exit) = &self.finished {
                let stop = Stop::Exited(exit.clone(), self.warpspeed.exit_status());
                return Ok(match goal {
                    Goal::Scan { .. } | Goal::ToEvent(_) => Outcome::Reached,
                    _ => Outcome::Stopped(stop),
                });
            }
            let event = self.warpspeed.event_index();
            self.high_water = self.high_water.max(event);
            if matches!(goal, Goal::ToEvent(to) if to == event) {
                return Ok(Outcome::Reached);
            }

            // The scan's end, if it's in this event. It comes before any preemption in it.
            let mut target = match &goal {
                Goal::Scan { to, .. } if to.event == event => Some((*to).clone()),
                _ => None,
            };
            let at_scan_end = target.is_some();
            if target.is_none() {
                target = self
                    .warpspeed
                    .next_preemption()
                    .map(|(instructions, registers)| Position {
                        event,
                        instructions,
                        registers,
                    });
            }

            let guest_event = if matches!(goal, Goal::Step) {
                self.step_guest(target.as_ref())?
            } else {
                self.run_guest(target.as_ref())?
            };
            match guest_event {
                GuestEvent::AtPosition if at_scan_end => return Ok(Outcome::Reached),
                GuestEvent::AtPosition => {
                    let exit = self.warpspeed.apply_preemption(self.vm.as_mut().expect("a VM"))?;
                    if let Some(stop) = self.after_event(exit, &mut goal)? {
                        return Ok(stop);
                    }
                }
                GuestEvent::Missed => return Ok(Outcome::Missed(event)),
                GuestEvent::Stepped => {}
                GuestEvent::Syscall => {
                    let exit = self.warpspeed.trap_handler(
                        self.vm.as_mut().expect("a VM"),
                        self.loader.as_ref().expect("a loader"),
                    )?;
                    if let Some(stop) = self.after_event(exit, &mut goal)? {
                        return Ok(stop);
                    }
                }
                GuestEvent::Hit(kind, addr) => {
                    if let Some(stop) = self.on_hit(kind, addr, &mut goal)? {
                        return Ok(stop);
                    }
                }
                GuestEvent::Other(VmRunResult::Brk) => {
                    self.finished = Some(ExitKind::Crash("guest trap (brk)".into()));
                }
                GuestEvent::Other(VmRunResult::Timer) => {}
                GuestEvent::Other(_) => {
                    self.finished = Some(ExitKind::Crash("guest exception".into()));
                }
            }
            if matches!(goal, Goal::Step) {
                return Ok(Outcome::Stopped(Stop::Step));
            }
        }
    }

    /// After replaying an event: exec, exit, checkpointing, and watchpoints on what the event
    /// wrote. Returns the outcome if that ends the run.
    fn after_event(&mut self, exit: ExitKind, goal: &mut Goal) -> Result<Option<Outcome>> {
        match exit {
            ExitKind::Continue => {}
            ExitKind::Exec(request) => {
                let vm = self.vm.take().expect("a VM");
                let loader = self.loader.take().expect("a loader");
                let (vm, loader) = self.warpspeed.exec(vm, loader, &request)?;
                self.vm = Some(vm);
                self.loader = Some(loader);
                // The old image's checkpoints are gone with its VM.
                self.checkpoints.clear();
                self.arm_debugger_breakpoints()?;
                for watchpoint in std::mem::take(&mut self.watchpoints) {
                    self.set_watchpoint(watchpoint, true)?;
                }
                self.take_checkpoint()?;
                return Ok(None);
            }
            exit => {
                self.finished = Some(exit);
                return Ok(None);
            }
        }

        let vm = self.vm_ref();
        let checkpointing = matches!(goal, Goal::Debugger | Goal::Step);
        if checkpointing && vm.guest_instructions() - self.instructions_at_checkpoint >= self.checkpoint_every
        {
            self.take_checkpoint()?;
        }

        // The event's recorded writes (e.g. a read() filling a buffer) can hit watchpoints.
        let written: Vec<(u64, usize)> = self.warpspeed.event_writes().to_vec();
        for watchpoint in self.watchpoints.clone() {
            if watchpoint.kind == WatchKind::Read {
                continue;
            }
            let hit = written.iter().find(|&&(addr, len)| {
                addr < watchpoint.addr + watchpoint.len && watchpoint.addr < addr + len as u64
            });
            if hit.is_some() {
                if let Some(stop) = self.on_hit(HitKind::Watchpoint(watchpoint), watchpoint.addr, goal)? {
                    return Ok(Some(stop));
                }
            }
        }
        Ok(None)
    }

    /// Handles a debugger hit according to `goal`. Returns the outcome if it ends the run.
    fn on_hit(&mut self, kind: HitKind, addr: u64, goal: &mut Goal) -> Result<Option<Outcome>> {
        let hit = self.count_hit(kind, addr)?;
        if let HitKind::Breakpoint(addr) = kind {
            self.at_breakpoint = Some(addr);
        }
        match goal {
            Goal::Debugger | Goal::Step => {
                if hit.event >= self.report_hits_from {
                    return Ok(Some(Outcome::Stopped(hit.stop())));
                }
            }
            Goal::Scan { to, hits } => {
                // Stopped at where the scan's going: that's not before it.
                let is_end = hit.event == to.event && same_point(&hit.registers, &to.registers);
                if !is_end {
                    hits.push(hit);
                }
            }
            Goal::Land(target) => {
                if hit.event == target.event && hit.kind == target.kind && hit.nth == target.nth {
                    return Ok(Some(Outcome::Stopped(hit.stop())));
                }
            }
            Goal::ToEvent(_) => {}
        }
        Ok(None)
    }

    /// Executes one instruction, ignoring the debugger's breakpoints and watchpoints.
    fn single_step(&mut self) -> Result<GuestEvent> {
        let vm = self.vm();
        vm.single_step()?;
        Ok(match vm.run()? {
            VmRunResult::Step => GuestEvent::Stepped,
            VmRunResult::Svc => GuestEvent::Syscall,
            other => GuestEvent::Other(other),
        })
    }

    /// If stopped at a debugger breakpoint, executes its instruction.
    fn step_over_breakpoint(&mut self) -> Result<Option<GuestEvent>> {
        let Some(addr) = self.at_breakpoint.take() else {
            return Ok(None);
        };
        if self.vm_ref().vcpu.get_reg(av::Reg::PC)? != addr {
            return Ok(None);
        }
        self.single_step().map(Some)
    }

    /// Executes one instruction (or gets to `target`, if already there).
    fn step_guest(&mut self, target: Option<&Position>) -> Result<GuestEvent> {
        if let Some(target) = target {
            if same_point(&Registers::save(&self.vm_ref().vcpu)?, &target.registers) {
                return Ok(GuestEvent::AtPosition);
            }
        }
        match self.step_over_breakpoint()? {
            Some(event) => Ok(event),
            None => self.single_step(),
        }
    }

    /// Runs the guest until a syscall, a debugger hit, or `target` (or passing it).
    fn run_guest(&mut self, target: Option<&Position>) -> Result<GuestEvent> {
        match self.step_over_breakpoint()? {
            None | Some(GuestEvent::Stepped) => {}
            Some(event) => return Ok(event),
        }
        let Some(target) = target else {
            loop {
                let result = self.vm().run()?;
                match self.classify(result)? {
                    GuestEvent::Other(VmRunResult::Timer) => continue,
                    event => return Ok(event),
                }
            }
        };

        if let Some(event) = self.run_coarse(target)? {
            return Ok(event);
        }

        // Precise: the first breakpoint hit with the position's registers. Each hit retires at
        // least an instruction, so more hits than could possibly remain mean it was missed.
        let base = self.warpspeed.last_event_instructions();
        let progress = self.vm_ref().guest_instructions() - base;
        let max_hits = target.instructions.saturating_sub(progress) + MISSED_SLACK;
        self.vm()
            .set_hardware_breakpoint_slot(POSITION_SLOT, Some(target.registers.pc))?;
        let mut hits = 0u64;
        let event = loop {
            let result = self.vm().run()?;
            if let VmRunResult::HardwareBreakpoint = result {
                let registers = Registers::save(&self.vm_ref().vcpu)?;
                if same_point(&registers, &target.registers) {
                    break GuestEvent::AtPosition;
                }
                if self.breakpoints.contains(&registers.pc) {
                    break GuestEvent::Hit(HitKind::Breakpoint(registers.pc), registers.pc);
                }
                hits += 1;
                if hits > max_hits {
                    break GuestEvent::Missed;
                }
                self.vm().single_step()?;
                continue;
            }
            match self.classify(result)? {
                GuestEvent::Other(VmRunResult::Timer | VmRunResult::Step) => {}
                GuestEvent::Syscall => break GuestEvent::Missed,
                event => break event,
            }
        };
        self.vm().set_hardware_breakpoint_slot(POSITION_SLOT, None)?;
        Ok(event)
    }

    /// Runs the guest in timed slices to short of `target` (unless it's to be found carefully).
    /// Returns what happened instead, if something did.
    fn run_coarse(&mut self, target: &Position) -> Result<Option<GuestEvent>> {
        if self.careful.contains(&target.event) {
            return Ok(None);
        }
        let base = self.warpspeed.last_event_instructions();
        loop {
            let progress = self.vm_ref().guest_instructions() - base;
            let remaining = target.instructions as f64 - progress as f64 - POSITION_MARGIN as f64;
            let ns = remaining * 0.8 / self.max_instructions_per_ns;
            if ns < MIN_TIMER_NS {
                return Ok(None);
            }
            let vm = self.vm();
            vm.arm_timer(Duration::from_nanos(ns as u64))?;
            let result = vm.run()?;
            vm.disarm_timer()?;
            match self.classify(result)? {
                GuestEvent::Other(VmRunResult::Timer) => {}
                // The position comes before the next syscall.
                GuestEvent::Syscall => return Ok(Some(GuestEvent::Missed)),
                event => return Ok(Some(event)),
            }
        }
    }

    /// What a run's result means, stepping over a watched access so it completes.
    fn classify(&mut self, result: VmRunResult) -> Result<GuestEvent> {
        Ok(match result {
            VmRunResult::Svc => GuestEvent::Syscall,
            VmRunResult::HardwareBreakpoint => {
                let pc = self.vm_ref().vcpu.get_reg(av::Reg::PC)?;
                GuestEvent::Hit(HitKind::Breakpoint(pc), pc)
            }
            VmRunResult::Watchpoint { addr } => {
                let watchpoint = self
                    .watchpoints
                    .iter()
                    .copied()
                    .find(|w| w.addr <= addr && addr < w.addr + w.len.max(8))
                    .or_else(|| self.watchpoints.first().copied())
                    .context("hit a watchpoint that isn't set")?;
                let vm = self.vm();
                vm.single_step()?;
                match vm.run()? {
                    VmRunResult::Step => GuestEvent::Hit(HitKind::Watchpoint(watchpoint), addr),
                    other => GuestEvent::Other(other),
                }
            }
            other => GuestEvent::Other(other),
        })
    }
}

