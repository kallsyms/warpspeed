pub mod mig;
pub mod sysno;

include!(concat!(env!("OUT_DIR"), "/mrr.recordable.syscall.rs"));
