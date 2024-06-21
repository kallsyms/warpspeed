pub mod mig;
pub mod sysno;

include!(concat!(env!("OUT_DIR"), "/warpspeed.recordable.syscall.rs"));
