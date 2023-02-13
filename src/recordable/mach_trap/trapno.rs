#![allow(non_upper_case_globals, unused)]

// "Special" traps for arm
// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/osfmk/mach/arm/traps.h#L36
pub const MACH_ARM_TRAP_ABSTIME: u32 = 3;
pub const MACH_ARM_TRAP_CONTTIME: u32 = 4;

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/osfmk/kern/syscall_sw.c#L105
/*
:g/kern_invalid/d
:s/_kernelrpc_//
:%s/_trap//
:%s/\/\* \([0-9]*\) \*\/ "\(.*\)",/pub const \2: u32 = \1;/
*/

pub const mach_vm_allocate: u32 = 10;
pub const mach_vm_purgable_control: u32 = 11;
pub const mach_vm_deallocate: u32 = 12;
pub const task_dyld_process_info_notify_get: u32 = 13;
pub const mach_vm_protect: u32 = 14;
pub const mach_vm_map: u32 = 15;
pub const mach_port_allocate: u32 = 16;
pub const mach_port_deallocate: u32 = 18;
pub const mach_port_mod_refs: u32 = 19;
pub const mach_port_move_member: u32 = 20;
pub const mach_port_insert_right: u32 = 21;
pub const mach_port_insert_member: u32 = 22;
pub const mach_port_extract_member: u32 = 23;
pub const mach_port_construct: u32 = 24;
pub const mach_port_destruct: u32 = 25;
pub const mach_reply_port: u32 = 26;
pub const thread_self: u32 = 27;
pub const task_self: u32 = 28;
pub const host_self: u32 = 29;
pub const mach_msg: u32 = 31;
pub const mach_msg_overwrite: u32 = 32;
pub const semaphore_signal: u32 = 33;
pub const semaphore_signal_all: u32 = 34;
pub const semaphore_signal_thread: u32 = 35;
pub const semaphore_wait: u32 = 36;
pub const semaphore_wait_signal: u32 = 37;
pub const semaphore_timedwait: u32 = 38;
pub const semaphore_timedwait_signal: u32 = 39;
pub const mach_port_get_attributes: u32 = 40;
pub const mach_port_guard: u32 = 41;
pub const mach_port_unguard: u32 = 42;
pub const mach_generate_activity_id: u32 = 43;
pub const task_name_for_pid: u32 = 44;
pub const task_for_pid: u32 = 45;
pub const pid_for_task: u32 = 46;
pub const mach_msg2: u32 = 47;
pub const macx_swapon: u32 = 48;
pub const macx_swapoff: u32 = 49;
pub const thread_get_special_reply_port: u32 = 50;
pub const macx_triggers: u32 = 51;
pub const macx_backing_store_suspend: u32 = 52;
pub const macx_backing_store_recovery: u32 = 53;
pub const pfz_exit: u32 = 58;
pub const swtch_pri: u32 = 59;
pub const swtch: u32 = 60;
pub const thread_switch: u32 = 61;
pub const clock_sleep: u32 = 62;
pub const host_create_mach_voucher: u32 = 70;
pub const mach_voucher_extract_attr_recipe: u32 = 72;
pub const mach_port_type: u32 = 76;
pub const mach_port_request_notification: u32 = 77;
pub const mach_timebase_info: u32 = 89;
pub const mach_wait_until: u32 = 90;
pub const mk_timer_create: u32 = 91;
pub const mk_timer_destroy: u32 = 92;
pub const mk_timer_arm: u32 = 93;
pub const mk_timer_cancel: u32 = 94;
pub const mk_timer_arm_leeway: u32 = 95;
pub const debug_control_port_for_pid: u32 = 96;
pub const iokit_user_client: u32 = 100;
