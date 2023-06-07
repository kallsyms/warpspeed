use std::collections::HashMap;

use nix::libc::sysctl;

const KDBG_SUBCLSTYPE: u32 = 0x20000;
const KDBG_RANGETYPE: u32 = 0x40000;
const KDBG_TYPENONE: u32 = 0x80000;
const KDBG_VALCHECK: u32 = 0x200000;

const DBG_MACH: u32 = 0x1;
// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/kdebug.h#L160
const DBG_MACH_SCHED: u32 = 0x40;

// https://github.com/opensource-apple/xnu/blob/0a798f6738bc1db01281fc08ae024145e84df927/bsd/sys/kdebug.h#L1539
#[repr(C)]
struct kd_regtype {
    typ: nix::libc::c_uint,
    values: [nix::libc::c_uint; 4],
}

// https://github.com/opensource-apple/xnu/blob/0a798f6738bc1db01281fc08ae024145e84df927/bsd/sys/kdebug.h#L1419
#[repr(C)]
#[derive(Debug)]
pub struct kd_buf {
    pub timestamp: u64,
    pub args: [u64; 5],
    pub debugid: u32,
    pub cpuid: u32,
    _unused: u64,
}

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/kdebug_private.h#L472
#[repr(C)]
#[derive(Debug)]
pub struct kd_threadmap {
    pub tid: u64,
    pub valid: nix::libc::c_int,
    pub command: [nix::libc::c_char; 20],
}

pub fn init() -> Result<(), String> {
    unsafe {
        // Reset
        // kdv: kdebugRemove
        {
            let mut mib: [nix::libc::c_int; 3] = [
                nix::libc::CTL_KERN,
                nix::libc::KERN_KDEBUG,
                nix::libc::KERN_KDREMOVE,
            ];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as nix::libc::c_uint,
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
        // kdv: kdebugBufs
        {
            let mut mib: [nix::libc::c_int; 4] = [
                nix::libc::CTL_KERN,
                nix::libc::KERN_KDEBUG,
                nix::libc::KERN_KDSETBUF,
                8192 * 1024,
            ];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as nix::libc::c_uint,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDSETBUF".into());
            }
        }

        // Do we need to do this here if we do it again in PID filter?
        // kdv: kdebugBufs
        {
            let mut mib: [nix::libc::c_int; 3] = [
                nix::libc::CTL_KERN,
                nix::libc::KERN_KDEBUG,
                nix::libc::KERN_KDSETUP,
            ];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as nix::libc::c_uint,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDSETUP".into());
            }
        }

        // Set event filter
        // kdv: kdebugInit
        {
            let mut kr = kd_regtype {
                typ: KDBG_RANGETYPE,
                // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/kern/trace_codes#L407
                values: [0x140003C, 0x140003C, 0, 0],
            };
            let mut len = std::mem::size_of::<kd_regtype>();

            let mut mib: [nix::libc::c_int; 3] = [
                nix::libc::CTL_KERN,
                nix::libc::KERN_KDEBUG,
                nix::libc::KERN_KDSETREG,
            ];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as nix::libc::c_uint,
                &mut kr as *mut kd_regtype as *mut nix::libc::c_void,
                &mut len as *mut usize as *mut nix::libc::size_t,
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDSETREG".into());
            }
        }

        // Reinitialize buffers (defaults to their minimum size)
        // kdv: kdebugInit
        {
            let mut mib: [nix::libc::c_int; 3] = [
                nix::libc::CTL_KERN,
                nix::libc::KERN_KDEBUG,
                nix::libc::KERN_KDSETUP,
            ];
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as nix::libc::c_uint,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDSETUP".into());
            }
        }

        // Set PID filter
        // kdv: filterPID
        // {
        //     let mut kr = kd_regtype {
        //         typ: KDBG_TYPENONE, // unused
        //         values: [pid.as_raw() as u32, 1, 0, 0],
        //     };
        //     let mut len = std::mem::size_of::<kd_regtype>();
        //     let mut mib: [nix::libc::c_int; 3] = [
        //         nix::libc::CTL_KERN,
        //         nix::libc::KERN_KDEBUG,
        //         nix::libc::KERN_KDPIDTR,
        //     ];
        //     if sysctl(
        //         mib.as_mut_ptr(),
        //         mib.len() as nix::libc::c_uint,
        //         &mut kr as *mut _ as *mut nix::libc::c_void,
        //         &mut len as *mut _ as *mut nix::libc::size_t,
        //         std::ptr::null_mut(),
        //         0,
        //     ) < 0
        //     {
        //         return Err("KDPIDTR".into());
        //     }
        // }
    }

    Ok(())
}

pub fn enable() -> Result<(), String> {
    // kdv: kdebugEnable
    unsafe {
        let mut mib: [nix::libc::c_int; 4] = [
            nix::libc::CTL_KERN,
            nix::libc::KERN_KDEBUG,
            nix::libc::KERN_KDENABLE,
            1,
        ];
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as nix::libc::c_uint,
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

// Get map of tid -> pid
pub fn get_thread_map() -> Result<HashMap<u64, i32>, String> {
    let mut map = HashMap::new();

    unsafe {
        let mut rawmap: Vec<kd_threadmap> = Vec::with_capacity(1_000_000);
        let mut len = std::mem::size_of::<kd_threadmap>() * rawmap.capacity();
        let mut mib: [nix::libc::c_int; 3] = [
            nix::libc::CTL_KERN,
            nix::libc::KERN_KDEBUG,
            nix::libc::KERN_KDTHRMAP,
        ];

        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as nix::libc::c_uint,
            rawmap.as_mut_ptr() as *mut nix::libc::c_void,
            &mut len as *mut _ as *mut nix::libc::size_t,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err("KDTHRMAP".into());
        }

        for entry in rawmap {
            if entry.valid == 0 {
                break;
            }
            map.insert(entry.tid, entry.valid);
        }
    }

    Ok(map)
}

pub fn read() -> Result<kd_buf, String> {
    unsafe {
        let mut buf: kd_buf = std::mem::zeroed();
        let mut len = std::mem::size_of::<kd_buf>();
        let mut mib: [nix::libc::c_int; 3] = [
            nix::libc::CTL_KERN,
            nix::libc::KERN_KDEBUG,
            nix::libc::KERN_KDREADTR,
        ];
        loop {
            if sysctl(
                mib.as_mut_ptr(),
                mib.len() as nix::libc::c_uint,
                &mut buf as *mut _ as *mut nix::libc::c_void,
                &mut len as *mut _ as *mut nix::libc::size_t,
                std::ptr::null_mut(),
                0,
            ) < 0
            {
                return Err("KDREADTR".into());
            }

            if len != 0 {
                break;
            }

            len = std::mem::size_of::<kd_buf>();
            //std::thread::sleep(std::time::Duration::from_millis(1));
        }

        Ok(buf)
    }
}

pub fn disable() -> Result<(), String> {
    unsafe {
        let mut mib: [nix::libc::c_int; 4] = [
            nix::libc::CTL_KERN,
            nix::libc::KERN_KDEBUG,
            nix::libc::KERN_KDENABLE,
            0,
        ];
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as nix::libc::c_uint,
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
