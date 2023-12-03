#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

pub mod mach_vm {
    include!(concat!(env!("OUT_DIR"), "/mig__mach_vm_defs.rs"));
}
