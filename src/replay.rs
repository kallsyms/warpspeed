use log::debug;
use prost::Message;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::cli;
use crate::recordable::Trace;
use crate::warpspeed;

pub fn replay(args: &cli::ReplayArgs) {
    let trace_file = std::fs::read(&args.trace_filename).unwrap();
    let trace = Trace::decode(trace_file.as_slice()).unwrap();
    debug!("Loaded trace with {} events", trace.events.len());
    let target = trace.target.clone().unwrap();

    let warpspeed = Arc::new(Mutex::new(warpspeed::Warpspeed::new(
        trace,
        warpspeed::Mode::Replay,
    )));

    let mut app = appbox::AppBox::new(
        &PathBuf::from(&target.path),
        &target.arguments,
        &target.environment,
        warpspeed,
    )
    .unwrap();

    let ret = app.run();
    debug!("executor returned: {:?}", ret);
}
