use log::{debug, error, info, trace, warn};
use serde::{Serialize, Deserialize};

use crate::mach;

mod sysno;

#[derive(Debug, Serialize, Deserialize)]
enum SyscallData {
    Read {
        data: Vec<u8>,
    },
    ReturnOnly {
        ret_vals: [u64; 2],
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Syscall {
    pc: u64,
    syscall_number: u32,
    data: SyscallData,
}

pub fn record_syscall(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    clobbered_regs: [u64; 2],
) -> Option<Syscall>{
    let mut regs = unsafe {
        let mut regs: mach::arm_thread_state64_t = std::mem::zeroed();
        // This is still specified in terms of u32's (size=4). Guess it's a legacy thing?
        let mut count: u32 = (std::mem::size_of::<mach::arm_thread_state64_t>() / 4) as u32;
        let r = mach::thread_get_state(
            thread_port,
            mach::ARM_THREAD_STATE64 as i32,
            &mut regs as *mut _ as mach::thread_state_t,
            &mut count,
        );
        if r != mach::KERN_SUCCESS {
            warn!("thread_get_state failed: {}", mach::r_mach_error_string(r));
            return None;
        }
        regs
    };

    let ret_vals: [u64; 2] = regs.__x[0..2].try_into().unwrap();

    regs.__x[0] = clobbered_regs[0];
    regs.__x[1] = clobbered_regs[1];

    trace!("regs {:x?}", regs);

    let syscall_number: u32 = regs.__x[16] as u32;

    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/kern/syscalls.master#L45
    match syscall_number {
        sysno::SYS_read => {
            // store the data that was read
            let mut data: Vec<u8> = vec![0; regs.__x[2] as usize];
            let mut copy_size: mach::mach_vm_size_t = regs.__x[2];
            
            let r = unsafe {
                mach::mach_vm_read_overwrite(
                    task_port,
                    regs.__x[1],
                    regs.__x[2],
                    data.as_mut_ptr() as mach::mach_vm_address_t,
                    &mut copy_size,
                )
            };
            if r != mach::KERN_SUCCESS {
                warn!("vm_read_overwrite failed: {}", mach::r_mach_error_string(r));
            }

            Some(Syscall{
                pc: regs.__pc,
                syscall_number,
                data: SyscallData::Read {
                    data: data[..ret_vals[0] as usize].to_vec(),
                },
            })
        }
        sysno::SYS_write => {
            // capture retval
            Some(Syscall{
                pc: regs.__pc,
                syscall_number,
                data: SyscallData::ReturnOnly {
                    ret_vals,
                },
            })
        }
        _ => {
            warn!("Unhandled syscall {}", syscall_number);
            None
        }
    }
}
