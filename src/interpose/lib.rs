use nix::libc;
use paste::paste;

#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub struct __dyld_interpose {
    new: *const (),
    old: *const (),
}

/// Interpose the specified function with the given body.
/// Example:
/// interpose! {
///     unsafe fn exit(_status: i32) {
///         libc::exit(123);
///     }
/// }
#[macro_export]
macro_rules! interpose {
    //      Optional link_name specifier for $NOCANCEL and similar
    //      |                       Target function
    //      |                       |                     Arguments
    //      |                       |                     |               Return
    //      |                       |                     |               |
    ($(#[$link:meta])? unsafe fn $func:ident ( $($v:ident : $t:ty),* ) -> $r:ty $body:block) => {
        paste! {
            pub mod $func {
                #[allow(dead_code)]
                #[allow(non_upper_case_globals)]
                #[link_section="__DATA,__interpose"]
                pub static mut $func: $crate::__dyld_interpose = $crate::__dyld_interpose {
                    new: super::[<interpose_ $func>] as *const (),
                    old: super::$func as *const (),
                };
            }

            extern {
                $(#[$link])?
                pub fn $func ( $($v : $t),* ) -> $r;
            }

            pub unsafe extern fn [<interpose_ $func>] ( $($v : $t),* ) -> $r $body
        }
    };

    // Short version for void return
    (unsafe fn $func:ident ( $($v:ident : $t:ty),* ) $body:block) => {
        $crate::interpose! { unsafe fn $func( $($v : $t),* ) -> () $body }
    };
}

interpose! {
    unsafe fn exit(_status: i32) {
        exit(123);
    }
}

interpose! {
    #[link_name = "write$NOCANCEL"] unsafe fn write_nocancel(fildes: i32, buf: *const libc::c_void, nbyte: usize) -> () {
        println!("writing to {}", fildes);
        write_nocancel(fildes, buf, nbyte);
    }
}
