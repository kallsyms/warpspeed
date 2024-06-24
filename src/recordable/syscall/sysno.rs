#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

include!(concat!(env!("OUT_DIR"), "/syscall_h.rs"));

// https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/syscall_sw.c#L241
pub const TRAP_mach_vm_allocate: u64 = (-10i64) as u64;
pub const TRAP_mach_vm_deallocate: u64 = (-12i64) as u64;
pub const TRAP_mach_vm_protect: u64 = (-14i64) as u64;
pub const TRAP_mach_vm_map: u64 = (-15i64) as u64;
pub const TRAP_mach_port_allocate: u64 = (-16i64) as u64;
pub const TRAP_mach_port_deallocate: u64 = (-18i64) as u64;
pub const TRAP_mach_port_construct: u64 = (-24i64) as u64;
pub const TRAP_mach_port_destruct: u64 = (-25i64) as u64;
pub const TRAP_mach_msg2: u64 = (-47i64) as u64;
