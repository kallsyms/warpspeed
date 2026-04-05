use std::ffi::{CString, NulError};

pub struct CStringArray {
    // I think this can be done with lifetimes and phantomdata...
    _owned: Vec<CString>,
    pointers: Vec<*mut i8>,
}

impl CStringArray {
    pub fn new(strings: &[String]) -> Result<CStringArray, NulError> {
        let owned: Vec<CString> = strings
            .iter()
            .map(|a| CString::new(a.as_bytes()))
            .collect::<Result<_, _>>()?;

        let mut pointers: Vec<*mut i8> = owned.iter().map(|s| s.as_ptr() as *mut i8).collect();
        pointers.push(std::ptr::null_mut());

        Ok(CStringArray {
            _owned: owned,
            pointers,
        })
    }

    pub fn as_ptr(&self) -> *const *mut i8 {
        self.pointers.as_ptr()
    }
}

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/spawn.h#L62
pub const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;

#[cfg(test)]
mod tests {
    use super::CStringArray;
    use std::ffi::CStr;

    #[test]
    fn cstring_array_preserves_order_and_is_null_terminated() {
        let strings = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let array = CStringArray::new(&strings).unwrap();

        assert_eq!(array.pointers.len(), strings.len() + 1);
        assert!(array.pointers.last().unwrap().is_null());

        let actual = array.pointers[..strings.len()]
            .iter()
            .map(|ptr| unsafe { CStr::from_ptr(*ptr) }.to_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(actual, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn cstring_array_handles_empty_input() {
        let array = CStringArray::new(&[]).unwrap();

        assert_eq!(array.pointers.len(), 1);
        assert!(array.pointers[0].is_null());
    }

    #[test]
    fn cstring_array_rejects_interior_nuls() {
        assert!(CStringArray::new(&["bad\0string".to_string()]).is_err());
    }
}
