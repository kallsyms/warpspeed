#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use std::ffi::CStr;

include!(concat!(env!("OUT_DIR"), "/mach.rs"));

// Not sure why these aren't in the bindgen output...
pub const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0 as mach_msg_timeout_t;
pub const MACH_PORT_RIGHT_RECEIVE: mach_port_right_t = 1 as mach_port_right_t;

/// Returns a string representation of a mach error
pub fn r_mach_error_string(r: kern_return_t) -> &'static str {
    unsafe { CStr::from_ptr(mach_error_string(r)).to_str().unwrap() }
}

/// Checks the return value of a mach function and return an error if it's not KERN_SUCCESS
pub fn mach_check_return(r: kern_return_t) -> Result<(), &'static str> {
    if r != KERN_SUCCESS {
        Err(r_mach_error_string(r))
    } else {
        Ok(())
    }
}

// Defined as a macro, guessing that's why it's not in the bindings?
pub fn mach_task_self() -> mach_port_t {
    unsafe {
        mach_task_self_
    }
}