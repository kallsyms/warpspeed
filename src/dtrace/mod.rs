use std::{ffi::{CString, CStr}, collections::HashMap};
use log::{trace, debug, info, warn, error};
use nix::libc;

use crate::mach;
use crate::recordable::Recordable;

mod bindings;

// Syntactic sugar to make walking through the aggregate data easier.
// https://stackoverflow.com/a/32270215
extern "C" fn dtrace_agg_walk_handler(
    agg: *const bindings::dtrace_aggdata_t,
    arg: *mut libc::c_void,
) -> libc::c_int {
    let closure: &mut &mut dyn FnMut(*const bindings::dtrace_aggdata_t) -> bool = unsafe {
        &mut *(arg as *mut &mut dyn std::ops::FnMut(*const bindings::dtrace_aggdata) -> bool)
    };
    closure(agg) as libc::c_int
}

fn dtrace_aggregate_walk_cb<F>(handle: *mut bindings::dtrace_hdl, mut callback: F) -> libc::c_int
where
    F: FnMut(*const bindings::dtrace_aggdata_t) -> libc::c_int,
{
    let mut cb: &mut dyn FnMut(*const bindings::dtrace_aggdata_t) -> libc::c_int = &mut callback;
    let cb = &mut cb;
    unsafe {
        bindings::dtrace_aggregate_walk(
            handle,
            Some(dtrace_agg_walk_handler),
            cb as *mut _ as *mut libc::c_void,
        )
    }
}

pub struct ProbeDescription(pub Option<String>, pub Option<String>, pub Option<String>, pub Option<String>);

impl ProbeDescription {
    pub fn new(provider: Option<&str>, module: Option<&str>, function: Option<&str>, name: Option<&str>) -> Self {
        ProbeDescription(
            provider.map(|s| s.to_string()),
            module.map(|s| s.to_string()),
            function.map(|s| s.to_string()),
            name.map(|s| s.to_string()),
        )
    }

    fn to_program_description(&self) -> String {
        format!("{}:{}:{}:{}",
            self.0.as_ref().map(|s| s.as_str()).unwrap_or(""),
            self.1.as_ref().map(|s| s.as_str()).unwrap_or(""),
            self.2.as_ref().map(|s| s.as_str()).unwrap_or(""),
            self.3.as_ref().map(|s| s.as_str()).unwrap_or(""),
        )
    }

    fn matches(&self, probe: &bindings::dtrace_probedesc_t) -> bool {
        if let Some(provider) = &self.0 {
            if provider != &unsafe { CStr::from_ptr(probe.dtpd_provider.as_ptr()) }.to_string_lossy() {
                return false;
            }
        }
        if let Some(module) = &self.1 {
            if module != &unsafe { CStr::from_ptr(probe.dtpd_mod.as_ptr()) }.to_string_lossy() {
                return false;
            }
        }
        if let Some(function) = &self.2 {
            if function != &unsafe { CStr::from_ptr(probe.dtpd_func.as_ptr()) }.to_string_lossy() {
                return false;
            }
        }
        if let Some(name) = &self.3 {
            if name != &unsafe { CStr::from_ptr(probe.dtpd_name.as_ptr()) }.to_string_lossy() {
                return false;
            }
        }
        true
    }
}

type ProbeCallback = dyn Fn(mach::mach_port_t, mach::mach_port_t, HashMap<String, u64>) -> Option<Recordable>;

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
            let dtrace_handle = bindings::dtrace_open(/*version=*/3, 0, &mut err);
            if dtrace_handle.is_null() {
                return Err(format!("dtrace_open failed: {}", err));
            }

            // Option reference: https://docs.oracle.com/cd/E23824_01/html/E22973/gkzhi.html#scrolltoc
            let opt = CString::new("bufsize").unwrap();
            let val = CString::new("4096").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(bufsize) failed: {}", err));
            }

            let opt = CString::new("aggsize").unwrap();
            let val = CString::new("4096").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(aggsize) failed: {}", err));
            }

            // Set an aggregate interval of 1ns, so that snapshot and aggregate walking
            // always fetch new data.
            // https://github.com/apple-oss-distributions/dtrace/blob/05b1f5b12ead47eb14e4712e24a1b1a981498020/lib/libdtrace/common/dt_aggregate.c#L733
            let opt = CString::new("aggrate").unwrap();
            let val = CString::new("1ns").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), val.as_ptr()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(aggrate) failed: {}", err));
            }

            // Needed for raise() to work
            let opt = CString::new("destructive").unwrap();
            if bindings::dtrace_setopt(dtrace_handle, opt.as_ptr(), std::ptr::null()) != 0 {
                let err = bindings::dtrace_errno(dtrace_handle);
                return Err(format!("dtrace_setopt(destructive) failed: {}", err));
            }

            dtrace_handle
        };

        Ok(Self { handle, pending_library_probes: vec![], hooks: vec![] })
    }

    pub fn register_program<F>(&mut self, probe_description: ProbeDescription, program: &str, callback: F) -> Result<(), String> 
    where
        F: Fn(mach::mach_port_t, mach::mach_port_t, HashMap<String, u64>) -> Option<Recordable> + 'static,
    {
        let program_cstr = CString::new(probe_description.to_program_description() + program).unwrap();
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
                let err = String::from_utf8_lossy(CStr::from_ptr(bindings::dtrace_errmsg(self.handle, errno)).to_bytes()).to_string();
                return Err(format!("dtrace_program_strcompile failed: {} ({})", err, errno));
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

    pub fn dispatch(&self, task_port: mach::mach_port_t, thread_port: mach::mach_port_t) -> Option<Recordable> {
        // This is entirely a hack.
        // Aggregates obviously aren't supposed to be used this way,
        // however it's much easier to request getting data from aggregates on-demand
        // compared to getting data from the principal buffer.
        // This also means we don't have to do any string->int decoding, so that's nice.
        let mut description: bindings::dtrace_probedesc_t = unsafe { std::mem::zeroed() };
        let mut aggdata: HashMap<String, u64> = HashMap::new();

        unsafe {
            if bindings::dtrace_aggregate_snap(self.handle) == -1 {
                warn!(
                    "dtrace_aggregate_snap failed: {}",
                    CStr::from_ptr(bindings::dtrace_errmsg(
                        self.handle,
                        bindings::dtrace_errno(self.handle)
                    ))
                    .to_str()
                    .unwrap()
                );
            }

            let closure = |agg: *const bindings::dtrace_aggdata_t| {
                let desc = *((*agg).dtada_desc);
                let records: &[bindings::dtrace_recdesc] = std::slice::from_raw_parts(
                    &(*(*agg).dtada_desc).dtagd_rec as *const bindings::dtrace_recdesc_t,
                    (desc.dtagd_nrecs) as usize,
                );
                let mut vals: Vec<u64> = vec![];
                for rec in records {
                    let ptr = ((*agg).dtada_data).offset(rec.dtrd_offset as isize);
                    match rec.dtrd_size {
                        1 => vals.push(*(ptr as *const u8) as u64),
                        2 => vals.push(*(ptr as *const u16) as u64),
                        4 => vals.push(*(ptr as *const u32) as u64),
                        8 => vals.push(*(ptr as *const u64)),
                        _ => panic!("dtrace agg: unhandled size: {}", rec.dtrd_size),
                    }
                }
                let aggname = CStr::from_ptr(desc.dtagd_name).to_str().unwrap();
                //trace!("dtrace agg {} vals: {:?}", aggname, vals);
                // Only record aggregate keys which have a value set (i.e. were hit)
                if vals[2] != 0 {
                    description = *(*agg).dtada_pdesc;
                    trace!("description: {:?}", description);
                    // TODO: check if description is already set and it differs from the current one
                    aggdata.insert(aggname.to_owned(), vals[1]);
                }
                bindings::DTRACE_AGGWALK_NEXT as i32
            };

            dtrace_aggregate_walk_cb(self.handle, closure);
            bindings::dtrace_aggregate_clear(self.handle);
        }

        if aggdata.len() == 0 {
            warn!("No aggregate data found");
            return None;
        }

        unsafe {
            trace!("probe: {:?}", CStr::from_ptr(description.dtpd_func.as_ptr()).to_str().unwrap());
        }
        trace!("aggdata: {:?}", aggdata);

        for (probe, hook) in &self.hooks {
            if probe.matches(&description) {
                return hook(task_port, thread_port, aggdata);
            }
        }

        warn!("No hook found for probe {:?}", description);
        None
    }
}