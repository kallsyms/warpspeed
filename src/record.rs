use log::debug;
use log::{error, info, trace, warn};
use std::fs::File;
use std::io::Write;
use std::time::Duration;

use crate::cli;
use crate::mach;
use crate::recordable;
use crate::util;
use crate::warpspeed;

use recordable::{log_event::Event, trace::Target, LogEvent, Trace};

pub fn record(args: &cli::RecordArgs) {
    let target = Target {
        path: args.executable.clone(),
        arguments: args.arguments.clone(),
        environment: vec![], // TODO
    };

    let _vm = hyperpom::applevisor::VirtualMachine::new(); // DO NOT REMOVE
    let gdata: warpspeed::GlobalData = Default::default();
    let ldata = warpspeed::LocalData {
        trace: Trace {
            target: Some(target),
            events: vec![],
        },
        ..Default::default()
    };

    let loader = warpspeed::MachOLoader::new(&args.executable, &args.arguments)
        .expect("could not create loader");

    // dynamically allocated physical memory must be <0x1000_0000, which is where our 1:1 mappings begins
    let config = hyperpom::config::ExecConfig::builder(0x1000_0000)
        .coverage(false)
        .build();

    let mut executor = hyperpom::core::Executor::<_, _, _>::new(config, loader, ldata, gdata)
        .expect("could not create executor");

    executor.init().expect("could not init executor");
    executor
        .vcpu
        .set_reg(hyperpom::applevisor::Reg::LR, 0xdeadf000)
        .unwrap();

    let ret = executor.run(None);
    debug!("executor returned: {:?}", ret);

    let mut output = File::create(&args.trace_filename).unwrap();
    output
        .write_all(prost::Message::encode_to_vec(&executor.ldata.trace).as_slice())
        .unwrap();
}
