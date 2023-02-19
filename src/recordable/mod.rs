use serde::{Deserialize, Serialize};

pub mod syscall;
pub mod mach_trap;
pub mod scheduling;

#[derive(Serialize, Deserialize, Debug)]
pub enum Recordable {
    Syscall(syscall::Syscall),
    MachTrap(mach_trap::MachTrap),
    Scheduling(scheduling::Scheduling),
}