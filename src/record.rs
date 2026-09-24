use anyhow::Result;
use appbox::gdb::GdbHooks;
use appbox::guest::{
    Decision, ExecRequest, Guest, GuestEnd, GuestFault, Hooks, Outcome, Preemption, Program,
    Resume, Syscall, ThreadCx,
};
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::cli;
use crate::recordable;
use crate::warpspeed::{self, Warpspeed};

use recordable::{trace::Target, Trace};

/// Records what the guest does into a trace.
struct Recorder(Arc<Mutex<Warpspeed>>);

impl Recorder {
    fn warpspeed(&self) -> MutexGuard<'_, Warpspeed> {
        self.0.lock().unwrap()
    }
}

impl Hooks for Recorder {
    fn start(&mut self, t: &mut ThreadCx) -> Result<Resume> {
        warpspeed::ensure_time_shared(t)?;
        Ok(Resume::Continue)
    }

    fn syscall(&mut self, t: &mut ThreadCx, call: &Syscall) -> Result<Decision> {
        self.warpspeed().record_syscall(t, call)?;
        Ok(Decision::Default)
    }

    fn syscall_done(&mut self, t: &mut ThreadCx, call: &Syscall, outcome: &Outcome) -> Result<()> {
        self.warpspeed().record_syscall_done(t, call, outcome)
    }

    fn preempted(&mut self, t: &mut ThreadCx, preemption: &Preemption) -> Result<()> {
        self.warpspeed().record_preemption(t, preemption)
    }

    fn fault(&mut self, t: &mut ThreadCx, fault: &GuestFault) -> Result<Resume> {
        warpspeed::log_fault(t, fault);
        Ok(Resume::End(fault.crash()))
    }

    fn exec(&mut self, t: &mut ThreadCx, _request: &ExecRequest) -> Result<()> {
        self.warpspeed().exec_done(t);
        Ok(())
    }
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

    let warpspeed = Arc::new(Mutex::new(Warpspeed::new(Trace {
        target: Some(target),
        events: vec![],
        shared_files: vec![],
    })?));

    let mut guest = Guest::builder(Program::new(&args.executable, argv, env))
        .count_instructions()
        .hooks(Recorder(warpspeed.clone()));
    if let Some(port) = args.gdb_port {
        guest = guest.hooks(GdbHooks::new(port, args.gdb_wait)?);
    }
    let end = guest.run()?;

    let mut output = File::create(&args.trace_filename)?;
    let warpspeed = warpspeed.lock().unwrap();
    output.write_all(prost::Message::encode_to_vec(&warpspeed.trace).as_slice())?;

    if let GuestEnd::Crashed { reason, .. } = end {
        anyhow::bail!("guest crashed: {reason}");
    }
    Ok(())
}
