use log::{info, trace, warn};

use crate::mach;

include!(concat!(env!("OUT_DIR"), "/mrr.recordable.syscall.rs"));

mod sysno;

pub fn record_syscall(
    task_port: mach::mach_port_t,
    thread_port: mach::mach_port_t,
    clobbered_regs: [u64; 2],
) -> Syscall {
    let mut regs = mach::mrr_get_regs(thread_port);

    let rv0 = regs.__x[0];
    let rv1 = regs.__x[1];

    regs.__x[0] = clobbered_regs[0];
    regs.__x[1] = clobbered_regs[1];

    let syscall_number: u32 = regs.__x[16] as u32;

    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/kern/syscalls.master#L45
    match syscall_number {
        sysno::SYS_read => {
            // store the data that was read (or errno)
            let result = if (regs.__x[2] as i32) < 0 {
                syscall::read::Result::Error(regs.__x[2])
            } else {
                let mut data: Vec<u8> = vec![0; rv0 as usize];
                let mut copy_size: mach::mach_vm_size_t = rv0;

                unsafe {
                    mach::mach_check_return(mach::mach_vm_read_overwrite(
                        task_port,
                        regs.__x[1],
                        rv0,
                        data.as_mut_ptr() as mach::mach_vm_address_t,
                        &mut copy_size,
                    ))
                    .unwrap();
                }

                syscall::read::Result::Data(data)
            };

            Syscall {
                syscall_number,
                data: Some(syscall::Data::Read(syscall::Read {
                    result: Some(result),
                })),
            }
        }
        sysno::SYS_write | sysno::SYS_write_nocancel => {
            // capture retval
            Syscall {
                syscall_number,
                data: Some(syscall::Data::ReturnOnly(syscall::ReturnOnly { rv0, rv1 })),
            }
        }
        _ => {
            warn!("Unhandled syscall {}", syscall_number);
            Syscall {
                syscall_number,
                data: None,
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
        Some(syscall::Data::Read(read_data)) => unsafe {
            match &read_data.result {
                None => {
                    unreachable!();
                }
                Some(syscall::read::Result::Error(err)) => {
                    regs.__x[0] = *err;
                    regs.__x[1] = 0;
                }
                Some(syscall::read::Result::Data(data)) => {
                    mach::mach_check_return(mach::mach_vm_write(
                        task_port,
                        regs.__x[1],
                        data.as_ptr() as mach::vm_offset_t,
                        data.len() as mach::mach_msg_type_number_t,
                    ))
                    .unwrap();
                    regs.__x[0] = data.len() as u64;
                    regs.__x[1] = 0;
                }
            }
        },
        Some(syscall::Data::ReturnOnly(ret_vals)) => {
            // Show when/what the child writes to stdout
            if (syscall.syscall_number == sysno::SYS_write
                || syscall.syscall_number == sysno::SYS_write_nocancel)
                && regs.__x[0] == 1
            {
                let mut data: Vec<u8> = vec![0; ret_vals.rv0 as usize];
                let mut copy_size: mach::mach_vm_size_t = ret_vals.rv0;

                unsafe {
                    mach::mach_check_return(mach::mach_vm_read_overwrite(
                        task_port,
                        regs.__x[1],
                        ret_vals.rv0,
                        data.as_mut_ptr() as mach::mach_vm_address_t,
                        &mut copy_size,
                    ))
                    .unwrap();
                }

                info!(
                    "Child wrote to stdout: {:?}",
                    std::str::from_utf8(&data).unwrap()
                );
            }

            regs.__x[0] = ret_vals.rv0;
            regs.__x[1] = ret_vals.rv1;
        }
        None => {
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
