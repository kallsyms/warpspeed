use anyhow::Result;
use appbox::gdb::{GdbCommand, GdbFeatures, GdbNotification, GdbResponse};
use appbox::hyperpom::crash::ExitKind;
use appbox::vm::Watchpoint;
use log::{debug, info, warn};
use prost::Message;

use crate::cli;
use crate::recordable::Trace;
use crate::replayer::{Replayer, Stop};

pub fn replay(args: &cli::ReplayArgs) -> Result<()> {
    let trace_file = std::fs::read(&args.trace_filename)?;
    let trace = Trace::decode(trace_file.as_slice())?;
    debug!("Loaded trace with {} events", trace.events.len());

    let mut replayer = Replayer::new(trace)?;
    // For testing recovering from overshooting a preemption point.
    if let Some(rate) = std::env::var("WARPSPEED_TEST_FIRST_ATTEMPT_INSTRUCTIONS_PER_NS")
        .ok()
        .and_then(|rate| rate.parse().ok())
    {
        replayer.assume_max_instructions_per_ns(rate);
    }

    let Some(port) = args.gdb_port else {
        return finished(replayer.run_to_end()?);
    };
    debug_with_gdb(&mut replayer, port)
}

fn finished(stop: Stop) -> Result<()> {
    if let Stop::Exited(ExitKind::Crash(reason), _) = stop {
        anyhow::bail!("guest crashed: {reason}");
    }
    Ok(())
}

/// Replays as a debugger connected on `port` directs, starting stopped at the beginning.
fn debug_with_gdb(replayer: &mut Replayer, port: u16) -> Result<()> {
    let (command_sender, command_receiver) = std::sync::mpsc::channel();
    let (response_sender, response_receiver) = std::sync::mpsc::channel();
    let notifications = appbox::gdb::start_gdb_server(
        port,
        command_sender,
        response_receiver,
        None,
        GdbFeatures {
            reverse_continue: true,
            reverse_step: false,
        },
    )?;
    info!("Waiting for GDB connection on port {port}...");

    let respond = |result: Result<()>| {
        let response = match result {
            Ok(()) => GdbResponse::Ok,
            Err(err) => {
                warn!("{err:#}");
                GdbResponse::Error(1)
            }
        };
        response_sender.send(response).unwrap();
    };

    while let Ok(command) = command_receiver.recv() {
        let stop = match command {
            GdbCommand::Continue => replayer.cont()?,
            GdbCommand::Step => replayer.step()?,
            GdbCommand::BackwardsContinue => replayer.reverse_cont()?,
            GdbCommand::BackwardsStep => {
                warn!("stepping backwards isn't supported yet");
                Stop::Step
            }
            GdbCommand::Kill => return Ok(()),
            GdbCommand::AddBreakpoint { addr, .. } => {
                respond(replayer.set_breakpoint(addr, true));
                continue;
            }
            GdbCommand::RemoveBreakpoint { addr, .. } => {
                respond(replayer.set_breakpoint(addr, false));
                continue;
            }
            GdbCommand::AddWatchpoint { addr, len, kind } => {
                respond(replayer.set_watchpoint(Watchpoint { addr, len, kind }, true));
                continue;
            }
            GdbCommand::RemoveWatchpoint { addr, len, kind } => {
                respond(replayer.set_watchpoint(Watchpoint { addr, len, kind }, false));
                continue;
            }
            other => {
                appbox::gdb::handle_command(other, replayer.vm(), &response_sender);
                continue;
            }
        };
        debug!("stopped: {stop:?}");
        let notification = match stop {
            Stop::Breakpoint | Stop::Step => GdbNotification::Stop(5),
            Stop::Watchpoint { kind, addr } => GdbNotification::Watchpoint { kind, addr },
            Stop::Start => GdbNotification::ReplayLogBegin,
            Stop::Exited(ExitKind::Crash(_), _) => GdbNotification::Stop(11),
            Stop::Exited(_, status) => GdbNotification::Exited(status.unwrap_or(0) as u8),
        };
        if notifications.send(notification).is_err() {
            break;
        }
    }
    Ok(())
}
