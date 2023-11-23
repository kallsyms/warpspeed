pub mod mach_traps;
pub mod syscall;

include!(concat!(env!("OUT_DIR"), "/mrr.recordable.syscall.rs"));
