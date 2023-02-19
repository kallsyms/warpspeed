use serde::{Deserialize, Serialize};

pub mod mach_trap;
pub mod scheduling;
pub mod syscall;

#[derive(Serialize, Deserialize, Debug)]
pub struct Recordable {
    pub pc: u64,
    pub event: Event,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Event {
    Syscall(syscall::Syscall),
    MachTrap(mach_trap::MachTrap),
    Scheduling(scheduling::Scheduling),
}
