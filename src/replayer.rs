//! Replaying a recording, forwards and backwards, under a debugger's control.
//!
//! Replay runs as appbox guest [`Hooks`] and a [`Scheduler`]: the hooks replay syscalls from the
//! recording and stop for the debugger, and the scheduler runs each thread exactly to where it
//! was preempted (and to wherever else replay is headed). The debugger's commands are taken while
//! the guest is stopped (in a hook), and set where replay heads next ([`Goal`]).
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
//! found by the scheduler's [`Slice::At`]: timed runs of the guest, by its approximate
//! instruction count, to short of the position, then a hardware breakpoint on its pc until the
//! registers match. A debugger hit is exact: the nth hit of that breakpoint or watchpoint since
//! an event.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use appbox::gdb::{GdbCommand, GdbFeatures, GdbNotification, GdbServer};
use appbox::guest::{
    Decision, ExecRequest, Guest, GuestEnd, Hooks, Outcome, Preempt, Program, Registers, Resume,
    Scheduler, Slice, Stop, Syscall, Target, ThreadCx, WatchKind, Watchpoint,
    MAX_INSTRUCTIONS_PER_NS,
};
use log::{debug, info, warn};

use crate::recordable::Trace;
use crate::warpspeed::{self, ReplayState, Warpspeed};

/// Guest instructions between checkpoints.
const CHECKPOINT_EVERY: u64 = 50_000_000;

/// Why replay stopped, to tell the debugger.
#[derive(Clone, Debug)]
enum DebugStop {
    /// At one of the debugger's breakpoints.
    Breakpoint,
    /// After a single step.
    Step,
    /// After an access to `addr`, watched by a `kind` watchpoint.
    Watchpoint { kind: WatchKind, addr: u64 },
    /// Went backwards to the start of the recording (or, after an exec, of the new image).
    Start,
    Ended(GuestEnd),
}

impl DebugStop {
    fn notification(&self) -> GdbNotification {
        match *self {
            DebugStop::Breakpoint | DebugStop::Step => GdbNotification::Stop(5),
            DebugStop::Watchpoint { kind, addr } => GdbNotification::Watchpoint { kind, addr },
            DebugStop::Start => GdbNotification::ReplayLogBegin,
            DebugStop::Ended(GuestEnd::Exited(status)) => GdbNotification::Exited(status as u8),
            DebugStop::Ended(GuestEnd::Crashed { signal, .. }) => {
                GdbNotification::Stop(signal as u8)
            }
        }
    }
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
    fn stop(&self) -> DebugStop {
        match self.kind {
            HitKind::Breakpoint(_) => DebugStop::Breakpoint,
            HitKind::Watchpoint(watchpoint) => DebugStop::Watchpoint {
                kind: watchpoint.kind,
                addr: self.addr,
            },
        }
    }
}

struct Checkpoint {
    appbox: appbox::guest::Checkpoint,
    state: ReplayState,
    registers: Registers,
    /// Checkpoints taken before, to judge its age when thinning them out.
    sequence: u64,
}

impl Checkpoint {
    fn position(&self) -> Position {
        Position {
            event: self.event(),
            instructions: 0,
            registers: self.registers.clone(),
        }
    }

    fn event(&self) -> usize {
        self.state.event_index()
    }
}

/// Where replay is headed.
enum Goal {
    /// The debugger's next breakpoint or watchpoint hit, or the end.
    Debugger,
    /// After one instruction.
    Step,
    /// Reverse-continue: from checkpoint `index` to `end`, silently, collecting the debugger's
    /// hits before it.
    Scan { index: usize, end: Position, hits: Vec<Hit> },
    /// Reverse-continue: from checkpoint `index` to `hit`, the last before where it started.
    Land { index: usize, hit: Hit },
    /// Reverse-step: to the start of the target's event, then [`Goal::Trail`].
    ToTrail(Position),
    /// Reverse-step: from the start of `target`'s event, to shortly before it (once `near`), then
    /// stepping to it, noting the state before it.
    Trail {
        target: Position,
        near: bool,
        previous: Option<Registers>,
    },
    /// Reverse-step: to the start of event `event`, then to where the event after it began: its
    /// thread's preemption ([`Goal::ReplayTo`]) or syscall ([`Goal::BackOut`]).
    ToBeforeEvent(usize),
    /// Reverse-step: to event `event`'s syscall, then back to before its svc.
    BackOut(usize),
    /// Reverse-step: to the position, then stop.
    ReplayTo(Position),
}

/// What replaying needs to know besides the recording: where it's going, its checkpoints, and the
/// debugger's breakpoints and watchpoints.
struct Replayer {
    warpspeed: Warpspeed,
    debugger: Option<GdbServer>,
    /// The debugger's.
    breakpoints: Vec<u64>,
    watchpoints: Vec<Watchpoint>,
    goal: Goal,
    /// A stop to report to the debugger before running on (see [`Slice::Stop`]).
    pending_stop: Option<DebugStop>,
    /// Whether a checkpoint was restored since last cleared.
    restored: bool,
    /// Oldest first; the first is where replay (or the current image) started.
    checkpoints: Vec<Checkpoint>,
    next_sequence: u64,
    instructions_at_checkpoint: u64,
    checkpoint_every: u64,
    /// Events whose positions to find without timing the guest first: slow, but can't overshoot.
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
}

/// Replays `trace`, under `debugger`'s control if there is one (starting stopped at the
/// beginning). `max_instructions_per_ns` is for testing recovering from overshooting a
/// preemption: the guest is assumed to run no faster than this until the first miss.
pub fn replay(
    trace: Trace,
    debugger: Option<u16>,
    max_instructions_per_ns: Option<f64>,
) -> Result<GuestEnd> {
    let target = trace.target.clone().context("trace missing target")?;
    let debugger = debugger
        .map(|port| {
            let server = GdbServer::start(
                port,
                GdbFeatures {
                    reverse_continue: true,
                    reverse_step: true,
                },
            );
            info!("Waiting for GDB connection on port {port}...");
            server
        })
        .transpose()?;
    let replayer = Arc::new(Mutex::new(Replayer {
        warpspeed: Warpspeed::new(trace)?,
        debugger,
        breakpoints: Vec::new(),
        watchpoints: Vec::new(),
        goal: Goal::Debugger,
        pending_stop: None,
        restored: false,
        checkpoints: Vec::new(),
        next_sequence: 0,
        instructions_at_checkpoint: 0,
        checkpoint_every: std::env::var("WARPSPEED_CHECKPOINT_EVERY")
            .ok()
            .and_then(|every| every.parse().ok())
            .unwrap_or(CHECKPOINT_EVERY),
        careful: BTreeSet::new(),
        max_instructions_per_ns: max_instructions_per_ns.unwrap_or(MAX_INSTRUCTIONS_PER_NS),
        high_water: 0,
        hit_counts: HashMap::new(),
        hit_counts_event: 0,
        report_hits_from: 0,
    }));
    Guest::builder(Program::new(
        target.path,
        target.arguments,
        target.environment,
    ))
    .count_instructions()
    .hooks(Replay(replayer.clone()))
    .scheduler(Replay(replayer))
    .run()
}

fn same_point(a: &Registers, b: &Registers) -> bool {
    a.pc == b.pc && a.sp == b.sp && a.x == b.x && a.q == b.q && a.cpsr >> 28 == b.cpsr >> 28
}

impl Replayer {
    fn event(&self) -> usize {
        self.warpspeed.event_index()
    }

    fn position(&self, t: &ThreadCx) -> Result<Position> {
        Ok(Position {
            event: self.event(),
            instructions: t.guest_instructions() - self.warpspeed.last_event_instructions(),
            registers: t.registers()?,
        })
    }

    /// `position`, in the current event, as a target for the scheduler.
    fn target(&self, position: &Position) -> Target {
        Target {
            instructions: self.warpspeed.last_event_instructions() + position.instructions,
            registers: position.registers.clone(),
            careful: self.careful.contains(&position.event),
            max_instructions_per_ns: self.max_instructions_per_ns,
        }
    }

    /// Where the goal ends, if it's a position.
    fn end(&self) -> Option<&Position> {
        match &self.goal {
            Goal::Scan { end, .. } | Goal::ReplayTo(end) => Some(end),
            _ => None,
        }
    }

    /// Takes the debugger's breakpoints and watchpoints out of the VM, or puts them back.
    fn arm(&self, t: &mut ThreadCx, armed: bool) -> Result<()> {
        for &addr in &self.breakpoints {
            match armed {
                true => t.add_breakpoint(addr)?,
                false => t.remove_breakpoint(addr)?,
            }
        }
        for &watchpoint in &self.watchpoints {
            match armed {
                true => t.add_watchpoint(watchpoint)?,
                false => t.remove_watchpoint(watchpoint)?,
            }
        }
        Ok(())
    }

    /// Reports `stop` to the debugger, if there is one, and takes its commands until it resumes
    /// replay.
    fn debug(&mut self, t: &mut ThreadCx, stop: Option<DebugStop>) -> Result<Resume> {
        self.goal = Goal::Debugger;
        self.arm(t, true)?;
        let Some(debugger) = &self.debugger else {
            return Ok(Resume::Continue);
        };
        debug!("stopped: {stop:?}");
        if let Some(stop) = stop {
            if debugger.notify(stop.notification()).is_err() {
                return Ok(Resume::End(GuestEnd::Exited(0)));
            }
        }
        while let Some(command) = debugger.recv() {
            if debugger.handle(&command, t) {
                self.breakpoints = t.breakpoints();
                self.watchpoints = t.watchpoints();
                continue;
            }
            match command {
                GdbCommand::Continue => return Ok(Resume::Continue),
                GdbCommand::Step => {
                    self.goal = Goal::Step;
                    return Ok(Resume::Step);
                }
                GdbCommand::BackwardsContinue => {
                    self.reverse_cont(t)?;
                    return Ok(Resume::Continue);
                }
                GdbCommand::BackwardsStep => {
                    self.reverse_step(t)?;
                    return Ok(Resume::Continue);
                }
                GdbCommand::Kill => break,
                command => unreachable!("{command:?} is handled by the server"),
            }
        }
        Ok(Resume::End(GuestEnd::Exited(0)))
    }

    /// Heads backwards to the debugger's previous breakpoint or watchpoint hit, or the start.
    fn reverse_cont(&mut self, t: &mut ThreadCx) -> Result<()> {
        let end = self.position(t)?;
        // The latest checkpoint before where replay is.
        let index = self
            .checkpoints
            .iter()
            .rposition(|checkpoint| {
                checkpoint.event() < end.event
                    || (checkpoint.event() == end.event
                        && !same_point(&checkpoint.registers, &end.registers))
            })
            .unwrap_or(0);
        self.goal = Goal::Scan {
            index,
            end,
            hits: Vec::new(),
        };
        self.restore(t, index)
    }

    /// Heads backwards by one instruction: to the state the guest was in before the current
    /// one, which is found by stepping forwards to here from shortly before.
    fn reverse_step(&mut self, t: &mut ThreadCx) -> Result<()> {
        let target = self.position(t)?;
        self.arm(t, false)?;
        let index = self.checkpoint_before(target.event);
        self.goal = Goal::ToTrail(target);
        self.restore(t, index)
    }

    /// A reverse-continue's scan got to its end.
    fn scan_done(&mut self, t: &mut ThreadCx) -> Result<()> {
        let Goal::Scan {
            index, mut hits, ..
        } = std::mem::replace(&mut self.goal, Goal::Debugger)
        else {
            unreachable!("not scanning");
        };
        if let Some(hit) = hits.pop() {
            debug!("reverse-continue: landing on {hit:?}");
            self.goal = Goal::Land { index, hit };
            return self.restore(t, index);
        }
        if index == 0 {
            return self.stop_at_start(t);
        }
        self.goal = Goal::Scan {
            index: index - 1,
            end: self.checkpoints[index].position(),
            hits: Vec::new(),
        };
        self.restore(t, index - 1)
    }

    fn stop_at_start(&mut self, t: &mut ThreadCx) -> Result<()> {
        self.goal = Goal::Debugger;
        self.restore(t, 0)?;
        self.pending_stop = Some(DebugStop::Start);
        Ok(())
    }

    /// Trailing a reverse-step's target: whether to step on, having noted where the guest is.
    fn trail(&mut self, t: &mut ThreadCx) -> Result<bool> {
        let registers = t.registers()?;
        let Goal::Trail {
            target, previous, ..
        } = &mut self.goal
        else {
            unreachable!("not trailing");
        };
        if !same_point(&registers, &target.registers) {
            *previous = Some(registers);
            return Ok(true);
        }
        let target = target.clone();
        match previous.take() {
            // The instruction count is the target's, as the count drifts while stepping.
            Some(registers) => {
                self.goal = Goal::ReplayTo(Position {
                    registers,
                    ..target.clone()
                });
                self.restore(t, self.checkpoint_before(target.event))?;
            }
            // It's the first instruction since the previous event, so go to just before that.
            None if target.event == self.checkpoints[0].event() => self.stop_at_start(t)?,
            None => {
                let event = target.event - 1;
                self.goal = Goal::ToBeforeEvent(event);
                self.restore(t, self.checkpoint_before(event))?;
            }
        }
        Ok(false)
    }

    /// Trailing a reverse-step's target passed it, so the instruction count led the timed runs
    /// astray: tries again carefully, or, if that was careful, gives up and stays put.
    fn trail_passed(&mut self) -> Result<()> {
        let Goal::Trail { target, .. } = &self.goal else {
            unreachable!("not trailing");
        };
        let target = target.clone();
        if self.careful.insert(target.event) {
            self.goal = Goal::ToTrail(target);
        } else {
            warn!("couldn't step backwards, staying put: stepping to {target:?} passed it");
            self.goal = Goal::ReplayTo(target);
        }
        Ok(())
    }

    /// Starts over towards the goal, from the checkpoint it started from.
    fn restart(&mut self, t: &mut ThreadCx) -> Result<()> {
        let index = match &self.goal {
            Goal::Debugger | Goal::Step => self.checkpoint_before(self.event()),
            Goal::Scan { index, .. } | Goal::Land { index, .. } => *index,
            Goal::ToTrail(position) | Goal::ReplayTo(position) => {
                self.checkpoint_before(position.event)
            }
            Goal::Trail { target, .. } => self.checkpoint_before(target.event),
            Goal::ToBeforeEvent(event) | Goal::BackOut(event) => self.checkpoint_before(*event),
        };
        match &mut self.goal {
            Goal::Scan { hits, .. } => hits.clear(),
            Goal::Trail { target, .. } => self.goal = Goal::ToTrail(target.clone()),
            Goal::BackOut(event) => self.goal = Goal::ToBeforeEvent(*event),
            _ => {}
        }
        self.restore(t, index)
    }

    /// The latest checkpoint at or before the start of event `event`.
    fn checkpoint_before(&self, event: usize) -> usize {
        self.checkpoints
            .iter()
            .rposition(|checkpoint| checkpoint.event() <= event)
            .unwrap_or(0)
    }

    fn take_checkpoint(&mut self, t: &mut ThreadCx) -> Result<()> {
        let appbox = t.checkpoint()?;
        self.instructions_at_checkpoint = t.guest_instructions();
        self.checkpoints.push(Checkpoint {
            appbox,
            state: self.warpspeed.state(),
            registers: t.registers()?,
            sequence: self.next_sequence,
        });
        self.next_sequence += 1;
        self.thin_checkpoints(t)
    }

    /// Keeps at most two checkpoints of each power-of-two age (in checkpoints taken since), and
    /// always the first.
    fn thin_checkpoints(&mut self, t: &mut ThreadCx) -> Result<()> {
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
                t.discard_checkpoint(&checkpoint.appbox)?;
            }
        }
        debug!("{} checkpoints", self.checkpoints.len());
        Ok(())
    }

    /// Goes back to checkpoint `index`, discarding later ones.
    fn restore(&mut self, t: &mut ThreadCx, index: usize) -> Result<()> {
        self.checkpoints.truncate(index + 1);
        let checkpoint = &self.checkpoints[index];
        t.restore(&checkpoint.appbox)?;
        self.warpspeed
            .set_state(checkpoint.state.clone(), t.guest_instructions());
        self.warpspeed.set_quiet_until(self.high_water);
        self.instructions_at_checkpoint = t.guest_instructions();
        self.hit_counts.clear();
        self.hit_counts_event = self.event();
        self.pending_stop = None;
        self.restored = true;
        Ok(())
    }

    /// Counts a hit of `kind` at the current event, and returns what to tell the debugger about
    /// it, if anything.
    fn hit(&mut self, t: &ThreadCx, kind: HitKind, addr: u64) -> Result<Option<DebugStop>> {
        let event = self.event();
        if self.hit_counts_event != event {
            self.hit_counts.clear();
            self.hit_counts_event = event;
        }
        let nth = self.hit_counts.entry(kind).or_default();
        *nth += 1;
        let hit = Hit {
            event,
            kind,
            nth: *nth,
            addr,
            registers: t.registers()?,
        };
        Ok(match &mut self.goal {
            Goal::Debugger | Goal::Step => {
                (hit.event >= self.report_hits_from).then(|| hit.stop())
            }
            Goal::Scan { end, hits, .. } => {
                // Stopped at where the scan's going: that's not before it.
                let is_end = hit.event == end.event && same_point(&hit.registers, &end.registers);
                if !is_end {
                    hits.push(hit);
                }
                None
            }
            Goal::Land { hit: target, .. } => {
                let landed =
                    hit.event == target.event && hit.kind == target.kind && hit.nth == target.nth;
                landed.then(|| hit.stop())
            }
            _ => None,
        })
    }

    /// After replaying an event: checkpointing, and watchpoints on what the event wrote.
    fn after_event(&mut self, t: &mut ThreadCx) -> Result<()> {
        let checkpointing = matches!(self.goal, Goal::Debugger | Goal::Step);
        if checkpointing
            && t.guest_instructions() - self.instructions_at_checkpoint >= self.checkpoint_every
        {
            self.take_checkpoint(t)?;
        }

        // The event's recorded writes (e.g. a read() filling a buffer) can hit watchpoints.
        let written = self.warpspeed.event_writes().to_vec();
        for watchpoint in self.watchpoints.clone() {
            if watchpoint.kind == WatchKind::Read {
                continue;
            }
            let hit = written.iter().any(|&(addr, len)| {
                addr < watchpoint.addr + watchpoint.len && watchpoint.addr < addr + len as u64
            });
            if hit {
                if let Some(stop) = self.hit(t, HitKind::Watchpoint(watchpoint), watchpoint.addr)? {
                    self.pending_stop = Some(stop);
                    break;
                }
            }
        }
        Ok(())
    }

    fn watchpoint_at(&self, addr: u64) -> Result<Watchpoint> {
        let mut watchpoints = self.watchpoints.iter();
        watchpoints
            .clone()
            .find(|w| w.addr <= addr && addr < w.addr + w.len.max(8))
            .or_else(|| watchpoints.next())
            .copied()
            .context("hit a watchpoint that isn't set")
    }
}

/// [`Replayer`] as the guest's hooks and scheduler (which share it).
struct Replay(Arc<Mutex<Replayer>>);

impl Replay {
    fn replayer(&self) -> MutexGuard<'_, Replayer> {
        self.0.lock().unwrap()
    }
}

impl Hooks for Replay {
    fn start(&mut self, t: &mut ThreadCx) -> Result<Resume> {
        warpspeed::ensure_time_shared(t)?;
        let mut replayer = self.replayer();
        replayer.take_checkpoint(t)?;
        replayer.debug(t, None)
    }

    fn syscall(&mut self, t: &mut ThreadCx, call: &Syscall) -> Result<Decision> {
        let mut replayer = self.replayer();
        match replayer.goal {
            Goal::Trail { .. } => {
                replayer.trail_passed()?;
                replayer.restart(t)?;
                return Ok(Decision::Default);
            }
            Goal::BackOut(_) => {
                let mut registers = t.registers()?;
                registers.pc -= 4;
                t.set_registers(&registers)?;
                replayer.goal = Goal::Debugger;
                replayer.pending_stop = Some(DebugStop::Step);
                return Ok(Decision::Resumed);
            }
            _ => {}
        }
        replayer.warpspeed.replay_syscall(t, call)
    }

    fn syscall_done(&mut self, t: &mut ThreadCx, _call: &Syscall, outcome: &Outcome) -> Result<()> {
        let mut replayer = self.replayer();
        if replayer.warpspeed.replay_syscall_done(t, outcome)? {
            replayer.after_event(t)?;
        }
        Ok(())
    }

    fn stopped(&mut self, t: &mut ThreadCx, stop: &Stop) -> Result<Resume> {
        let mut replayer = self.replayer();
        let report = match *stop {
            Stop::Breakpoint { addr } => replayer.hit(t, HitKind::Breakpoint(addr), addr)?,
            Stop::Watchpoint { addr, .. } => {
                let watchpoint = replayer.watchpoint_at(addr)?;
                replayer.hit(t, HitKind::Watchpoint(watchpoint), addr)?
            }
            Stop::Step if matches!(replayer.goal, Goal::Trail { .. }) => {
                return Ok(match replayer.trail(t)? {
                    true => Resume::Step,
                    false => Resume::Continue,
                });
            }
            Stop::Step => Some(replayer.pending_stop.take().unwrap_or(DebugStop::Step)),
            Stop::Scheduled => replayer.pending_stop.take(),
        };
        match report {
            Some(stop) => replayer.debug(t, Some(stop)),
            None => Ok(Resume::Continue),
        }
    }

    fn exec(&mut self, t: &mut ThreadCx, _request: &ExecRequest) -> Result<()> {
        let mut replayer = self.replayer();
        replayer.warpspeed.exec_done(t);
        // The old image's checkpoints are gone with its VM.
        replayer.checkpoints.clear();
        replayer.arm(t, true)?;
        replayer.take_checkpoint(t)
    }

    fn ending(&mut self, t: &mut ThreadCx, end: &GuestEnd) -> Result<Resume> {
        let mut replayer = self.replayer();
        if let Goal::Scan { .. } = replayer.goal {
            replayer.scan_done(t)?;
            return Ok(Resume::Continue);
        }
        if replayer.debugger.is_none() {
            return Ok(Resume::End(end.clone()));
        }
        // Going on is only possible from somewhere else.
        loop {
            replayer.restored = false;
            let resume = replayer.debug(t, Some(DebugStop::Ended(end.clone())))?;
            if replayer.restored || matches!(resume, Resume::End(_)) {
                return Ok(resume);
            }
        }
    }
}

impl Scheduler for Replay {
    fn slice(&mut self, _t: &mut ThreadCx) -> Result<Slice> {
        let mut replayer = self.replayer();
        let event = replayer.event();
        replayer.high_water = replayer.high_water.max(event);
        if replayer.pending_stop.is_some() {
            return Ok(Slice::Stop);
        }

        match replayer.goal {
            Goal::ToTrail(ref target) if target.event == event => {
                replayer.goal = Goal::Trail {
                    target: target.clone(),
                    near: false,
                    previous: None,
                };
            }
            Goal::ToBeforeEvent(before) if before == event => {
                replayer.goal = match replayer.warpspeed.next_preemption() {
                    Some((instructions, registers)) => Goal::ReplayTo(Position {
                        event,
                        instructions,
                        registers,
                    }),
                    None => Goal::BackOut(event),
                };
            }
            _ => {}
        }
        if let Goal::Trail { ref target, near, .. } = replayer.goal {
            if near {
                // Stepping the rest of the way.
                return Ok(Slice::Unlimited);
            }
            let target = replayer.target(target);
            if let Goal::Trail { near, .. } = &mut replayer.goal {
                *near = true;
            }
            return Ok(Slice::Near(target));
        }

        // The goal's end, if it's in this event, comes before any preemption in it.
        if let Some(end) = replayer.end().filter(|end| end.event == event) {
            return Ok(Slice::At(replayer.target(end)));
        }
        Ok(match replayer.warpspeed.next_preemption() {
            Some((instructions, registers)) => Slice::At(replayer.target(&Position {
                event,
                instructions,
                registers,
            })),
            None => Slice::Unlimited,
        })
    }

    fn preempt(&mut self, t: &mut ThreadCx) -> Result<Preempt> {
        let mut replayer = self.replayer();
        let event = replayer.event();
        if replayer.end().is_some_and(|end| end.event == event) {
            match replayer.goal {
                Goal::Scan { .. } => replayer.scan_done(t)?,
                _ => {
                    replayer.goal = Goal::Debugger;
                    replayer.pending_stop = Some(DebugStop::Step);
                }
            }
            return Ok(Preempt::Continue);
        }
        if let Goal::Trail { .. } = replayer.goal {
            return Ok(match replayer.trail(t)? {
                true => Preempt::Step,
                false => Preempt::Continue,
            });
        }
        // Where the thread was preempted when recording. appbox only knows about one thread on
        // replay, so the switch is replay's to make.
        replayer.warpspeed.apply_preemption(t)?;
        replayer.after_event(t)?;
        Ok(Preempt::Continue)
    }

    fn missed(&mut self, t: &mut ThreadCx, _target: &Target) -> Result<()> {
        let mut replayer = self.replayer();
        replayer.max_instructions_per_ns = MAX_INSTRUCTIONS_PER_NS;
        if let Goal::Trail { .. } = replayer.goal {
            replayer.trail_passed()?;
            return replayer.restart(t);
        }
        let event = replayer.event();
        replayer.careful.insert(event);
        if let Goal::Debugger | Goal::Step = replayer.goal {
            info!("Restarting replay to find the preemption at event {event} carefully");
            // What's been replayed up to it was already reported.
            replayer.report_hits_from = replayer.report_hits_from.max(event + 1);
        }
        replayer.restart(t)
    }
}
