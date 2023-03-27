use libc::sysctl;

const KDBG_SUBCLSTYPE: u32 = 0x20000;
const KDBG_TYPENONE: u32 = 0x80000;

const DBG_MACH: u32 = 0x1;
const DBG_MACH_IPC: u32 = 0x20;

#[repr(C)]
// https://github.com/opensource-apple/xnu/blob/0a798f6738bc1db01281fc08ae024145e84df927/bsd/sys/kdebug.h#L1539
struct kd_regtype {
    typ: libc::c_uint,
    values: [libc::c_uint; 4],
}

#[repr(C)]
#[derive(Debug)]
// https://github.com/opensource-apple/xnu/blob/0a798f6738bc1db01281fc08ae024145e84df927/bsd/sys/kdebug.h#L1419
pub struct kd_buf {
    pub timestamp: u64,
    pub args: [u64; 5],
    pub debugid: u32,
    pub cpuid: u32,
    _unused: u64,
}

pub fn init(pid: nix::unistd::Pid) -> Result<(), String> {
    unsafe {
        // Reset
        {
            let mut mib: [libc::c_int; 3] =
                [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDREMOVE];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDREMOVE".into());
            }
        }

        // Setup buffer size
        // {
        //     let mut mib: [libc::c_int; 4] =
        //         [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDSETBUF, 1024];
        //     if sysctl(
        //         mib.as_mut_ptr(),
        //         mib.len() as libc::c_uint,
        //         std::ptr::null_mut(),
        //         std::ptr::null_mut(),
        //         std::ptr::null_mut(),
        //         0,
        //     ) < 0
        //     {
        //         return Err("KDSETBUF".into());
        //     }
        // }

        // Set event filter
        {
            // TODO: KDBG_VALCHECK against exactly task_suspend
            let mut kr = kd_regtype {
                typ: KDBG_SUBCLSTYPE,
                values: [DBG_MACH, DBG_MACH_IPC, 0, 0],
            };
            let mut len = std::mem::size_of::<kd_regtype>();

            let mut mib: [libc::c_int; 3] =
                [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDSETREG];
            if (sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                &mut kr as *mut kd_regtype as *mut libc::c_void,
                &mut len as *mut usize as *mut libc::size_t,
                std::ptr::null_mut(),
                0,
            ) < 0)
            {
                return Err("KDSETREG".into());
            }
        }

        // Set PID filter
        {
            let mut kr = kd_regtype {
                typ: 0,
                values: [pid.as_raw() as u32, 1, 0, 0],
            };
            let mut len = std::mem::size_of::<kd_regtype>();
            let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDPIDTR];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                &mut kr as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::size_t,
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDPIDTR".into());
            }
        }

        // Reinitialize buffers (defaults to their minimum size)
        {
            let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDSETUP];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDSETUP".into());
            }
        }
    }

    Ok(())
}

pub fn enable() -> Result<(), String> {
    unsafe {
        let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDENABLE, 1];
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err("KDENABLE".into());
        }
    }

    Ok(())
}

pub fn read() -> Result<kd_buf, String> {
    unsafe {
        // Block until ready
        // fml this requires a minimum number of events that we don't control
        // "Block until there are `kd_buffer_trace.kdb_storage_threshold` storage units filled..."
        // .kdb_storage_threshold is set to .kdb_storage_count / 2,
        // and .kdb_storage_count is set to a minimum of ncpus * 4
        let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDBUFWAIT];
        let mut timeout_ms = 1;
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut timeout_ms as *mut _ as *mut libc::size_t,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err("KDBUFWAIT".into());
        }

        let mut buf: kd_buf = std::mem::zeroed();
        let mut len = std::mem::size_of::<kd_buf>();
        let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDREADTR];
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut buf as *mut _ as *mut libc::c_void,
            &mut len as *mut _ as *mut libc::size_t,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err("KDREADTR".into());
        }

        Ok(buf)
    }
}

pub fn disable() -> Result<(), String> {
    unsafe {
        let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_KDEBUG, libc::KERN_KDENABLE, 0];
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err("KDENABLE".into());
        }
    }

    Ok(())
}
