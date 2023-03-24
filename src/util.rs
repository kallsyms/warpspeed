use nix::libc;
use nix::sys::ptrace;
use std::ffi::CString;

use crate::recordable::trace::Target;

struct CStringArray {
    // I think this can be done with lifetimes and phantomdata...
    owned: Vec<CString>,
    pointers: Vec<*mut i8>,
}

impl CStringArray {
    fn new(strings: &[String]) -> CStringArray {
        let owned: Vec<CString> = strings
            .iter()
            .map(|a| CString::new(a.as_bytes()).unwrap())
            .collect();

        let mut pointers: Vec<*mut i8> = owned.iter().map(|s| s.as_ptr() as *mut i8).collect();
        pointers.push(std::ptr::null_mut());

        CStringArray { owned, pointers }
    }

    fn as_ptr(&self) -> *const *mut i8 {
        self.pointers.as_ptr()
    }
}

pub fn ptrace_attachexc(pid: nix::unistd::Pid) -> nix::Result<()> {
    unsafe {
        nix::errno::Errno::result(libc::ptrace(
            ptrace::Request::PT_ATTACHEXC as ptrace::RequestType,
            pid.into(),
            std::ptr::null_mut(),
            0,
        ))
        .map(|_| ())
    }
}

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/spawn.h#L62
const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;

pub fn spawn_target(target: &Target) -> nix::unistd::Pid {
    unsafe {
        let mut pid: libc::pid_t = 0;

        let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
        let res = libc::posix_spawnattr_init(&mut attr);
        if res != 0 {
            panic!(
                "posix_spawnattr_init failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let res = libc::posix_spawnattr_setflags(
            &mut attr,
            (libc::POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_DISABLE_ASLR) as i16,
        );
        if res != 0 {
            panic!(
                "posix_spawnattr_setflags failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let executable = CString::new(target.path.clone()).unwrap();
        let mut all_args = vec![target.path.clone()];
        all_args.extend(target.arguments.clone());
        let argv = CStringArray::new(&all_args);
        let env = CStringArray::new(&target.environment);

        let res = libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            std::ptr::null(),
            &attr,
            argv.as_ptr(),
            env.as_ptr(), // TODO
        );
        if res != 0 {
            panic!("posix_spawn failed: {}", std::io::Error::last_os_error());
        }

        nix::unistd::Pid::from_raw(pid)
    }
}
