use log::debug;
use prost::Message;

use crate::cli;
use crate::recordable::Trace;
use crate::warpspeed;

pub fn replay(args: &cli::ReplayArgs) {
    let trace_file = std::fs::read(&args.trace_filename).unwrap();
    let trace = Trace::decode(trace_file.as_slice()).unwrap();
    debug!("Loaded trace with {} events", trace.events.len());
    let target = trace.target.clone().unwrap();

    let _vm = hyperpom::applevisor::VirtualMachine::new(); // DO NOT REMOVE
    let gdata: warpspeed::GlobalData = Default::default();
    let ldata = warpspeed::LocalData {
        trace,
        ..Default::default()
    };

    let loader = warpspeed::MachOLoader::new_replay_loader(&target.path, &target.arguments)
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
}
