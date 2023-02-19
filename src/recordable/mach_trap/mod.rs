use log::{trace, warn};
use serde::{Deserialize, Serialize};

use crate::mach;
mod trapno;

#[derive(Debug, Serialize, Deserialize)]
enum MachTrapData {
    Unhandled,
    ReturnOnly { ret_val: u64 },
    Timebase { data: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MachTrap {
    pub pc: u64,
    trap_number: u32,
    data: MachTrapData,
}

pub fn record_mach_trap(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    clobbered_regs: [u64; 1],
) -> MachTrap {
    let mut regs = mach::mrr_get_regs(thread_port);

    let ret_val: u64 = regs.__x[0];

    regs.__x[0] = clobbered_regs[0];
    regs.__pc -= 4;

    trace!("regs {:x?}", regs);

    let trap_number: u32 = (-(regs.__x[16] as i64)) as u32;

    match trap_number {
        trapno::MACH_ARM_TRAP_ABSTIME => {
            MachTrap {
                pc: regs.__pc,
                trap_number,
                data: MachTrapData::ReturnOnly { ret_val },
            }
        }
        trapno::MACH_ARM_TRAP_CONTTIME => {
            MachTrap {
                pc: regs.__pc,
                trap_number,
                data: MachTrapData::ReturnOnly { ret_val },
            }
        }
        trapno::mach_timebase_info => {
            let mut data: Vec<u8> = vec![0; 8];  // sizeof(mach_timebase_info)
            let mut copy_size: mach::mach_vm_size_t = 8;

            unsafe {
                mach::mach_check_return(mach::mach_vm_read_overwrite(
                    task_port,
                    regs.__x[0],
                    8,
                    data.as_mut_ptr() as mach::mach_vm_address_t,
                    &mut copy_size,
                ))
                .unwrap();
            }

            MachTrap {
                pc: regs.__pc,
                trap_number,
                data: MachTrapData::Timebase { data },
            }
        }
        _ => {
            warn!("Unhandled mach trap {}", trap_number);
            MachTrap {
                pc: regs.__pc,
                trap_number,
                data: MachTrapData::Unhandled,
            }
        }
    }
}

pub fn replay_mach_trap(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    trap: &MachTrap,
) -> bool {
    let mut regs = mach::mrr_get_regs(thread_port);

    if regs.__pc != trap.pc {
        panic!("PC mismatch: {:x} != {:x}", regs.__pc, trap.pc);
    }

    if regs.__x[16] as u32 != trap.trap_number {
        panic!(
            "Trap number mismatch: {:x} != {:x}",
            regs.__x[16], trap.trap_number
        );
    }

    match &trap.data {
        MachTrapData::Unhandled => {
            warn!(
                "Unhandled trap {}, not intercepting",
                trap.trap_number
            );
            // TODO: restore original instruction which SVC overwrote
            return false;
        }
        MachTrapData::ReturnOnly { ret_val } => {
            regs.__x[0] = *ret_val;
        }
        MachTrapData::Timebase { data } => {
            unsafe {
                mach::mach_check_return(mach::mach_vm_write(
                    task_port,
                    regs.__x[0],
                    data.as_ptr() as mach::vm_offset_t,
                    data.len() as mach::mach_msg_type_number_t,
                ))
                .unwrap();
            }
        }
    }

    regs.__pc += 4;
    mach::mrr_set_regs(thread_port, regs);

    true
}