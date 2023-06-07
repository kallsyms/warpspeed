use log::{info, trace, warn};

use crate::mach;

include!(concat!(env!("OUT_DIR"), "/mrr.recordable.syscall.rs"));

pub mod sysno;

pub fn replay_syscall(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    syscall: &Syscall,
) -> bool {
    let mut regs = mach::mrr_get_regs(thread_port);

    if regs.__x[16] as u32 != syscall.syscall_number {
        panic!(
            "Syscall number mismatch: {:x} != {:x}",
            regs.__x[16], syscall.syscall_number
        );
    }

    // TODO: side effects

    mach::mrr_set_regs(thread_port, regs);

    true
}
