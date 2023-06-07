#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

include!(concat!(env!("OUT_DIR"), "/warpspeed_loader_ffi.rs"));

// TODO: figure out why this is required (fails to link otherwise)
#[link(name = "warpspeed_loader", kind = "static")]
extern "C" {}
