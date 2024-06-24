use log::debug;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::cli;
use crate::recordable;
use crate::warpspeed;

use recordable::{trace::Target, Trace};

pub fn record(args: &cli::RecordArgs) {
    let mut argv = vec![args.executable.clone()];
    argv.extend_from_slice(&args.arguments);
    let env = vec![]; // TODO

    let target = Target {
        path: args.executable.clone(),
        arguments: argv.clone(),
        environment: env.clone(),
    };

    let warpspeed = Arc::new(Mutex::new(warpspeed::Warpspeed::new(
        Trace {
            target: Some(target),
            events: vec![],
        },
        warpspeed::Mode::Record,
    )));

    let mut app = appbox::AppBox::new(
        &PathBuf::from(&args.executable),
        &argv,
        &env,
        warpspeed.clone(),
    )
    .unwrap();

    let ret = app.run();
    debug!("executor returned: {:?}", ret);

    let mut output = File::create(&args.trace_filename).unwrap();
    output
        .write_all(prost::Message::encode_to_vec(&warpspeed.lock().unwrap().trace).as_slice())
        .unwrap();
}
