#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/mach_exc.rs"));

pub const MACH_EXCEPTION_RAISE: i32 = 2405;