#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

include!(concat!(env!("OUT_DIR"), "/syscall_h.rs"));

pub const TRAP_mach_vm_map: u64 = 0xfffffffffffffff1;
pub const TRAP_mach_vm_protect: u64 = 0xfffffffffffffff2;
pub const TRAP_mach_vm_deallocate: u64 = 0xfffffffffffffff4;
pub const TRAP_mach_vm_allocate: u64 = 0xfffffffffffffff6;
pub const TRAP_mach_msg2: u64 = 0xffffffffffffffd1;
