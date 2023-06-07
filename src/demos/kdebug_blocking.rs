use clap::Parser;

use mrr::kdebug;
use mrr::mach;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// PID to target
    #[clap(required = true)]
    pub pid: i32,
}

fn main() {
    let args = Cli::parse();

    let mut port: mach::task_t = 0;
    unsafe {
        mach::mach_check_return(mach::task_for_pid(
            mach::mach_task_self(),
            args.pid,
            &mut port,
        ))
        .unwrap();
    }
    let mut threads = vec![];
    for thread in mach::mrr_list_threads(port) {
        let mut info: mach::thread_identifier_info_data_t = unsafe { std::mem::zeroed() };
        let mut count: u32 =
            (std::mem::size_of::<mach::thread_identifier_info_data_t>() / 4) as u32;
        unsafe {
            mach::mach_check_return(mach::thread_info(
                thread,
                mach::THREAD_IDENTIFIER_INFO as u32,
                &mut info as *mut _ as *mut i32,
                &mut count,
            ))
            .unwrap();
        }
        threads.push(info.thread_id);
    }

    println!("Threads: {:?}", threads);

    kdebug::init().unwrap();
    kdebug::enable().unwrap();

    loop {
        let event = kdebug::read().unwrap();
        if threads.contains(&event.args[4]) {
            dbg!("{:?}", event);
        }
    }
}
