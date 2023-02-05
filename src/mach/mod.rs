use log::trace;
use std::ffi::CStr;

mod bindings;
pub use bindings::*;
pub mod mig;

// Make destructuring of code easier
pub const EXC_SOFT_SIGNAL64: i64 = EXC_SOFT_SIGNAL as i64;

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
    unsafe { mach_task_self_ }
}

// https://www.spaceflint.com/?p=150
// https://sourcegraph.com/github.com/hhhaiai/decompile/-/blob/bin/radareorg_radare2/libr/debug/p/native/xnu/xnu_excthreads.c?L455:23
pub fn mrr_set_exception_port(child: nix::unistd::Pid) -> (task_t, mach_port_name_t) {
    let mut task_port: task_t = 0;
    let mut exception_port: mach_port_name_t = 0;

    unsafe {
        mach_check_return(task_for_pid(mach_task_self(), child.into(), &mut task_port)).unwrap();
        trace!("task_port: {}", task_port);

        mach_check_return(mach_port_allocate(
            mach_task_self(),
            MACH_PORT_RIGHT_RECEIVE,
            &mut exception_port,
        ))
        .unwrap();
        trace!("exception_port: {}", exception_port);

        mach_check_return(mach_port_insert_right(
            mach_task_self(),
            exception_port,
            exception_port,
            MACH_MSG_TYPE_MAKE_SEND,
        ))
        .unwrap();
        mach_check_return(task_set_exception_ports(
            task_port,
            EXC_MASK_ALL,
            exception_port,
            (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES) as i32,
            THREAD_STATE_NONE, // Why does setting ARM_THREAD_STATE not cause us to go to the state handler?
        ))
        .unwrap();
        trace!("set exception port");

        let mut req_port: mach_port_t = 0;
        mach_check_return(mach_port_request_notification(
            mach_task_self(),
            task_port,
            MACH_NOTIFY_DEAD_NAME,
            0,
            exception_port,
            MACH_MSG_TYPE_MAKE_SEND_ONCE,
            &mut req_port,
        ))
        .unwrap();
    }

    (task_port, exception_port)
}

pub fn mrr_get_regs(thread_port: mach_port_t) -> arm_thread_state64_t {
    unsafe {
        let mut regs: arm_thread_state64_t = std::mem::zeroed();
        // This is still specified in terms of u32's (size=4). Guess it's a legacy thing?
        let mut count: u32 = (std::mem::size_of::<arm_thread_state64_t>() / 4) as u32;
        mach_check_return(thread_get_state(
            thread_port,
            ARM_THREAD_STATE64,
            &mut regs as *mut _ as thread_state_t,
            &mut count,
        ))
        .unwrap();
        regs
    }
}

pub fn mrr_set_regs(thread_port: mach_port_t, regs: arm_thread_state64_t) {
    unsafe {
        // This is still specified in terms of u32's (size=4). Guess it's a legacy thing?
        let count: u32 = (std::mem::size_of::<arm_thread_state64_t>() / 4) as u32;
        mach_check_return(thread_set_state(
            thread_port,
            ARM_THREAD_STATE64,
            &regs as *const _ as thread_state_t,
            count,
        ))
        .unwrap();
    }
}
