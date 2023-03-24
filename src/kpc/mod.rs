use nix::unistd::Pid;

// mod bindings;

#[link(name = "kperf", kind = "framework")]
extern "C" {
    fn kpc_force_all_ctrs_get(x: *mut i32) -> i32;
}

struct Monitor {}

impl Monitor {
    pub fn new(target: Pid) -> Result<Self, String> {
        let mut x: i32 = 0;
        unsafe { println!("{}", kpc_force_all_ctrs_get(&mut x)) };
        Ok(Monitor {})
    }
}
