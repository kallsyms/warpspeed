use anyhow::Result;
use appbox::guest::GuestEnd;
use log::debug;
use prost::Message;

use crate::cli;
use crate::recordable::Trace;
use crate::replayer;

pub fn replay(args: &cli::ReplayArgs) -> Result<()> {
    let trace_file = std::fs::read(&args.trace_filename)?;
    let trace = Trace::decode(trace_file.as_slice())?;
    debug!("Loaded trace with {} events", trace.events.len());

    // For testing recovering from overshooting a preemption point.
    let first_attempt_rate = std::env::var("WARPSPEED_TEST_FIRST_ATTEMPT_INSTRUCTIONS_PER_NS")
        .ok()
        .and_then(|rate| rate.parse().ok());

    let end = replayer::replay(trace, args.gdb_port, first_attempt_rate)?;
    if let (GuestEnd::Crashed { reason, .. }, None) = (end, args.gdb_port) {
        anyhow::bail!("guest crashed: {reason}");
    }
    Ok(())
}
