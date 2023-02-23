use log::{trace, warn};
use serde::{Deserialize, Serialize};

use crate::mach;

mod sysno;

#[derive(Debug, Serialize, Deserialize)]
enum SyscallData {
    Read { data: Vec<u8> },
    ReturnOnly { ret_vals: [u64; 2] },
    Unhandled,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Syscall {
    syscall_number: u32,
    data: SyscallData,
}

pub fn record_syscall(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    clobbered_regs: [u64; 2],
) -> Syscall {
    let mut regs = mach::mrr_get_regs(thread_port);

    let ret_vals: [u64; 2] = regs.__x[0..2].try_into().unwrap();

    regs.__x[0] = clobbered_regs[0];
    regs.__x[1] = clobbered_regs[1];

    let syscall_number: u32 = regs.__x[16] as u32;

    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/kern/syscalls.master#L45
    match syscall_number {
        sysno::SYS_read => {
            // store the data that was read
            let mut data: Vec<u8> = vec![0; regs.__x[2] as usize];
            let mut copy_size: mach::mach_vm_size_t = regs.__x[2];

            unsafe {
                mach::mach_check_return(mach::mach_vm_read_overwrite(
                    task_port,
                    regs.__x[1],
                    regs.__x[2],
                    data.as_mut_ptr() as mach::mach_vm_address_t,
                    &mut copy_size,
                ))
                .unwrap();
            }

            Syscall {
                syscall_number,
                data: SyscallData::Read {
                    data: data[..ret_vals[0] as usize].to_vec(),
                },
            }
        }
        sysno::SYS_write => {
            // capture retval
            Syscall {
                syscall_number,
                data: SyscallData::ReturnOnly { ret_vals },
            }
        }
        0 => {
            // HACK HACK HACK
            // FIXME: when we first start, we get STOP'd _before_ the first instruction has run
            // unlike every other time when we stop after PC has been adjusted forward.
            // This readjusts PC back forwards, but will need to be fixed properly (upstream?)
            // since syscall "0" is a valid syscall (indirect syscall).
            Syscall {
                syscall_number,
                data: SyscallData::Unhandled,
            }
        }
        _ => {
            warn!("Unhandled syscall {}", syscall_number);
            Syscall {
                syscall_number,
                data: SyscallData::Unhandled,
            }
        }
    }
}

pub fn replay_syscall(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    syscall: &Syscall,
) -> bool {
    let mut regs = mach::mrr_get_regs(thread_port);

    if regs.__x[16] as u32 != syscall.syscall_number {
        panic!(
            "Syscall number mismatch: {:x} != {:x}",
            regs.__x[16], syscall.syscall_number
        );
    }

    match &syscall.data {
        SyscallData::Read { data } => unsafe {
            mach::mach_check_return(mach::mach_vm_write(
                task_port,
                regs.__x[1],
                data.as_ptr() as mach::vm_offset_t,
                data.len() as mach::mach_msg_type_number_t,
            ))
            .unwrap();
        },
        SyscallData::ReturnOnly { ret_vals } => {
            regs.__x[0] = ret_vals[0];
            regs.__x[1] = ret_vals[1];
        }
        SyscallData::Unhandled => {
            warn!(
                "Unhandled syscall {}, not intercepting",
                syscall.syscall_number
            );
            return false;
        }
    }

    mach::mrr_set_regs(thread_port, regs);

    true
}

// TODO
#[derive(Debug, Serialize, Deserialize)]
pub struct MachSyscall {
    pc: u64,
    syscall_number: u32,
}
