use log::{debug, error, info, trace, warn};
use nix::libc;
use std::ffi::{CStr, CString};

use crate::mach;
use crate::recordable::Recordable;

mod bindings;

// Syntactic sugar to make walking through the buffer easier.
// https://stackoverflow.com/a/32270215
extern "C" fn dtrace_consume_rec_handler(
    pd: *const bindings::dtrace_probedata_t,
    rec: *const bindings::dtrace_recdesc_t,
    arg: *mut libc::c_void,
) -> libc::c_int {
    let closure: &mut &mut dyn FnMut(
        *const bindings::dtrace_probedata_t,
        *const bindings::dtrace_recdesc_t,
    ) -> bool = unsafe {
        &mut *(arg as *mut &mut dyn std::ops::FnMut(
            *const bindings::dtrace_probedata_t,
            *const bindings::dtrace_recdesc_t,
        ) -> bool)
    };
    closure(pd, rec) as libc::c_int
}

// Wrapper around dtrace_consume that takes a closure instead of a callback for `rf`.
// No `pf` is passed.
fn dtrace_consume_cb<F>(handle: *mut bindings::dtrace_hdl, mut callback: F) -> libc::c_int
where
    F: FnMut(*const bindings::dtrace_probedata_t, *const bindings::dtrace_recdesc_t) -> libc::c_int,
{
    let mut cb: &mut dyn FnMut(
        *const bindings::dtrace_probedata_t,
        *const bindings::dtrace_recdesc_t,
    ) -> libc::c_int = &mut callback;
    let cb = &mut cb;
    unsafe {
        bindings::dtrace_consume(
            handle,
            std::ptr::null_mut(),
            None,
            Some(dtrace_consume_rec_handler),
            cb as *mut _ as *mut libc::c_void,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDescription(
    pub Option<String>,
    pub Option<String>,
    pub Option<String>,
    pub Option<String>,
);

impl ProbeDescription {
    pub fn new(
        provider: Option<&str>,
        module: Option<&str>,
        function: Option<&str>,
        name: Option<&str>,
    ) -> Self {
        ProbeDescription(
            provider.map(|s| s.to_string()),
            module.map(|s| s.to_string()),
            function.map(|s| s.to_string()),
            name.map(|s| s.to_string()),
        )
    }

    fn to_program_description(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.0.as_ref().map(|s| s.as_str()).unwrap_or(""),
            self.1.as_ref().map(|s| s.as_str()).unwrap_or(""),
            self.2.as_ref().map(|s| s.as_str()).unwrap_or(""),
            self.3.as_ref().map(|s| s.as_str()).unwrap_or(""),
        )
    }

    fn matches(&self, probe: &ProbeDescription) -> bool {
        if let Some(provider) = &self.0 {
            if provider != probe.0.as_ref().unwrap() {
                return false;
            }
        }
        if let Some(module) = &self.1 {
            if module != probe.1.as_ref().unwrap() {
                return false;
            }
        }
        if let Some(function) = &self.2 {
            if function != probe.2.as_ref().unwrap() {
                return false;
            }
        }
        if let Some(name) = &self.3 {
            if name != probe.3.as_ref().unwrap() {
                return false;
            }
        }
        true
    }
}

impl From<*mut bindings::dtrace_probedesc_t> for ProbeDescription {
    fn from(probe: *mut bindings::dtrace_probedesc_t) -> Self {
        ProbeDescription(
            Some(
                unsafe { CStr::from_ptr((*probe).dtpd_provider.as_ptr()) }
                    .to_string_lossy()
                    .to_string(),
            ),
            Some(
                unsafe { CStr::from_ptr((*probe).dtpd_mod.as_ptr()) }
                    .to_string_lossy()
                    .to_string(),
            ),
            Some(
                unsafe { CStr::from_ptr((*probe).dtpd_func.as_ptr()) }
                    .to_string_lossy()
                    .to_string(),
            ),
            Some(
                unsafe { CStr::from_ptr((*probe).dtpd_name.as_ptr()) }
                    .to_string_lossy()
                    .to_string(),
            ),
        )
    }
}

type ProbeCallback = dyn Fn(mach::mach_port_t, mach::mach_port_t, &Vec<u64>) -> Option<Event>;

pub struct DTraceManager {
    handle: *mut bindings::dtrace_hdl,
    pending_library_probes: Vec<(String, ProbeDescription, Box<ProbeCallback>)>,
    hooks: Vec<(ProbeDescription, Box<ProbeCallback>)>,
}

impl Drop for DTraceManager {
    fn drop(&mut self) {
        unsafe {
            bindings::dtrace_stop(self.handle);
            bindings::dtrace_close(self.handle);
        }
    }
}

impl DTraceManager {
    pub fn new() -> Result<Self, String> {
        let handle = unsafe {
            let mut err: i32 = 0;
            let dtrace_handle = bindings::dtrace_open(/*version=*/ 3, 0, &mut err);
            if dtrace_handle.is_null() {
                return Err(format!("dtrace_open failed: {}", err));
            }

            // Option reference: https://docs.oracle.com/cd/E23824_01/html/E22973/gkzhi.html#scrolltoc
            let opt = CString::new("bufsize").unwrap();
            let val = CString::new("1k").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(bufsize) failed: {}", err));
            }

            // Set a switch rate of 1ns, so that calling dtrace_consume always fetches new data.
            // https://github.com/apple-oss-distributions/dtrace/blob/05b1f5b12ead47eb14e4712e24a1b1a981498020/lib/libdtrace/common/dt_consume.c#L2929
            let opt = CString::new("switchrate").unwrap();
            let val = CString::new("1ns").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(switchrate) failed: {}", err));
            }

            // Needed for raise() to work
            let opt = CString::new("destructive").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), std::ptr::null()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(destructive) failed: {}", err));
            }

            dtrace_handle
        };

        Ok(Self {
            handle,
            pending_library_probes: vec![],
            hooks: vec![],
        })
    }

    pub fn register_program<F>(
        &mut self,
        probe_description: ProbeDescription,
        program: &str,
        callback: F,
    ) -> Result<(), String>
    where
        F: Fn(mach::mach_port_t, mach::mach_port_t, &Vec<u64>) -> Option<Event> + 'static,
    {
        let program_cstr =
            CString::new(probe_description.to_program_description() + program).unwrap();
        debug!("register_program: {}", program_cstr.to_str().unwrap());

        unsafe {
            let prog = bindings::dtrace_program_strcompile(
                self.handle,
                program_cstr.as_ptr(),
                bindings::dtrace_probespec_DTRACE_PROBESPEC_NAME,
                0,
                0,
                std::ptr::null(),
            );
            if prog.is_null() {
                let errno = bindings::dtrace_errno(self.handle);
                let err = String::from_utf8_lossy(
                    CStr::from_ptr(bindings::dtrace_errmsg(self.handle, errno)).to_bytes(),
                )
                .to_string();
                return Err(format!(
                    "dtrace_program_strcompile failed: {} ({})",
                    err, errno
                ));
            }

            if bindings::dtrace_program_exec(self.handle, prog, std::ptr::null_mut()) != 0 {
                let err = bindings::dtrace_errno(self.handle);
                return Err(format!("dtrace_program_exec failed: {}", err));
            }
        }

        self.hooks.push((probe_description, Box::new(callback)));

        Ok(())
    }

    pub fn enable(&self) -> Result<(), String> {
        unsafe {
            if bindings::dtrace_go(self.handle) != 0 {
                let err = bindings::dtrace_errno(self.handle);
                Err(format!("dtrace_go failed: {}", err))
            } else {
                Ok(())
            }
        }
    }

    fn dispatch_one(
        &self,
        task_port: mach::mach_port_t,
        thread_port: mach::mach_port_t,
        pdesc: &ProbeDescription,
        trace_data: &Vec<u64>,
    ) -> Option<Event> {
        for (probe, hook) in &self.hooks {
            if probe.matches(&pdesc) {
                return hook(task_port, thread_port, trace_data);
            }
        }

        warn!("No hook found for probe {:?}", pdesc);
        return None;
    }

    pub fn dispatch(
        &self,
        task_port: mach::mach_port_t,
        thread_port: mach::mach_port_t,
    ) -> Vec<Event> {
        // The last probe hit in the closure
        let mut last_probe: Option<ProbeDescription> = None;
        // Accumulated data from the probe
        let mut trace_data: Vec<u64> = vec![];

        let mut events = vec![];

        unsafe {
            let closure = |data: *const bindings::dtrace_probedata_t,
                           record: *const bindings::dtrace_recdesc_t| {
                if record.is_null() {
                    return bindings::DTRACE_CONSUME_NEXT as i32;
                }

                let pdesc = ProbeDescription::from((*data).dtpda_pdesc);

                // This is a new probe, so we need to flush the previous one
                if last_probe.is_some() && last_probe.as_ref() != Some(&pdesc) {
                    if let Some(event) = self.dispatch_one(
                        task_port,
                        thread_port,
                        last_probe.as_ref().unwrap(),
                        &trace_data,
                    ) {
                        events.push(event);
                    }
                    trace_data.clear();
                }

                last_probe = Some(pdesc);

                let action = (*record).dtrd_action;
                match action as u32 {
                    bindings::DTRACEACT_DIFEXPR => trace_data.push(match (*record).dtrd_size {
                        1 => *((*data).dtpda_data as *const u8) as u64,
                        2 => *((*data).dtpda_data as *const u16) as u64,
                        4 => *((*data).dtpda_data as *const u32) as u64,
                        8 => *((*data).dtpda_data as *const u64),
                        _ => {
                            warn!("Unexpected size: {}", (*record).dtrd_size);
                            0
                        }
                    }),
                    bindings::DTRACEACT_RAISE => {}
                    bindings::DTRACEACT_STOP => {}
                    _ => {
                        warn!("Unexpected action: {}", action);
                    }
                }

                bindings::DTRACE_CONSUME_NEXT as i32
            };

            dtrace_consume_cb(self.handle, closure);
        }

        if let Some(pdesc) = last_probe {
            if let Some(event) = self.dispatch_one(task_port, thread_port, &pdesc, &trace_data) {
                events.push(event);
            }
        }

        events
    }
}
