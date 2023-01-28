use log::{debug, error, info, trace, warn};
use serde::{Serialize, Deserialize};

use crate::mach;

#[derive(Debug, Serialize, Deserialize)]
enum SyscallData {
    Read {
        data: Vec<u8>,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Syscall {
    pc: u64,
    data: SyscallData,
}

pub fn record_syscall(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    clobbered_regs: [u64; 2],
) -> Option<Syscall>{
    let mut regs = unsafe {
        let mut count = 68;  // ARM_THREAD_STATE64_COUNT
        let mut regs: [u64; 68] = [0; 68];
        let r = mach::thread_get_state(
            thread_port,
            6,  // ARM_THREAD_STATE64
            &mut regs as *mut _ as mach::thread_state_t,
            &mut count,
        );
        if r != mach::KERN_SUCCESS {
            warn!("thread_get_state failed: {}", mach::r_mach_error_string(r));
            return None;
        }
        regs
    };

    let ret_vals = regs[0..2].to_vec();

    regs[0] = clobbered_regs[0];
    regs[1] = clobbered_regs[1];

    trace!("regs {:x?}", regs);

    let syscall_number = regs[16];

    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/kern/syscalls.master#L45
    match syscall_number {
        3 => {
            // read. store the data that was read
            let mut data: Vec<u8> = vec![0; regs[2] as usize];
            let mut copy_size: mach::mach_vm_size_t = regs[2];
            
            let r = unsafe {
                mach::mach_vm_read_overwrite(
                    task_port,
                    regs[1],
                    regs[2],
                    data.as_mut_ptr() as mach::mach_vm_address_t,
                    &mut copy_size,
                )
            };
            if r != mach::KERN_SUCCESS {
                warn!("vm_read_overwrite failed: {}", mach::r_mach_error_string(r));
            }

            Some(Syscall{
                pc: regs[32],
                data: SyscallData::Read {
                    data: data[..ret_vals[0] as usize].to_vec(),
                },
            })
        }
        _ => {
            warn!("Unhandled syscall {}", syscall_number);
            None
        }
    }
}
