use log::{trace, warn};

use crate::mach;

mod trapno;

include!(concat!(env!("OUT_DIR"), "/mrr.recordable.mach_trap.rs"));

pub fn record_mach_trap(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    clobbered_regs: [u64; 1],
) -> MachTrap {
    let mut regs = mach::mrr_get_regs(thread_port);

    let ret_val: u64 = regs.__x[0];

    regs.__x[0] = clobbered_regs[0];

    // We treat the trap number as the positive version of the actual number passed in
    let trap_number: u32 = (-(regs.__x[16] as i64)) as u32;

    match trap_number {
        trapno::MACH_ARM_TRAP_ABSTIME | trapno::MACH_ARM_TRAP_CONTTIME => MachTrap {
            trap_number,
            data: Some(mach_trap::Data::ReturnOnly(ret_val)),
        },
        trapno::mach_timebase_info => {
            let mut data: Vec<u8> = vec![0; 8]; // sizeof(mach_timebase_info)
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
                trap_number,
                data: Some(mach_trap::Data::Timebase(mach_trap::Timebase { data })),
            }
        }
        _ => {
            warn!("Unhandled mach trap {}", trap_number);
            MachTrap {
                trap_number,
                data: None,
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

    let trap_number: u32 = (-(regs.__x[16] as i64)) as u32;

    if trap_number != trap.trap_number {
        panic!(
            "Trap number mismatch: {:x} != {:x}",
            trap_number, trap.trap_number
        );
    }

    match &trap.data {
        None => {
            warn!("Unhandled trap {}, not replaying", trap.trap_number);
            return false;
        }
        Some(mach_trap::Data::ReturnOnly(ret_val)) => {
            regs.__x[0] = *ret_val;
        }
        Some(mach_trap::Data::Timebase(data)) => {
            // This is completely correct as far as i can tell but causes desync???
            // unsafe {
            //     mach::mach_check_return(mach::mach_vm_write(
            //         task_port,
            //         regs.__x[0],
            //         data.as_ptr() as mach::vm_offset_t,
            //         data.len() as mach::mach_msg_type_number_t,
            //     ))
            //     .unwrap();
            // }
            return false;
        }
    }

    mach::mrr_set_regs(thread_port, regs);

    true
}
