use std::ffi::CString;

pub struct CStringArray {
    // I think this can be done with lifetimes and phantomdata...
    _owned: Vec<CString>,
    pointers: Vec<*mut i8>,
}

impl CStringArray {
    pub fn new(strings: &[String]) -> CStringArray {
        let owned: Vec<CString> = strings
            .iter()
            .map(|a| CString::new(a.as_bytes()).unwrap())
            .collect();

        let mut pointers: Vec<*mut i8> = owned.iter().map(|s| s.as_ptr() as *mut i8).collect();
        pointers.push(std::ptr::null_mut());

        CStringArray {
            _owned: owned,
            pointers,
        }
    }

    pub fn as_ptr(&self) -> *const *mut i8 {
        self.pointers.as_ptr()
    }
}

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/spawn.h#L62
pub const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;
