use log::{trace, warn};

use crate::mach;

pub mod trapno;

include!(concat!(env!("OUT_DIR"), "/mrr.recordable.mach_trap.rs"));

pub fn replay_mach_trap(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    trap: &MachTrap,
) -> bool {
    let mut regs = mach::mrr_get_regs(thread_port);

    let trap_number: u32 = (-(regs.__x[16] as i64)) as u32;

    if trap_number != trap.trap_number {
        panic!(
            "Trap number mismatch: {:x} != {:x}",
            trap_number, trap.trap_number
        );
    }

    // TODO: side effects

    mach::mrr_set_regs(thread_port, regs);

    true
}
