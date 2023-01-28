use std::process::Command;
use std::path::PathBuf;
use std::env;

#[derive(Debug)]
struct MachParseCallbacks;

impl bindgen::callbacks::ParseCallbacks for MachParseCallbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
        // kern_return_t's and mach_msg_option_t's are ints
        if name.starts_with("KERN_") || name.starts_with("MACH_RCV_") || name.starts_with("MACH_SEND_") {
            return Some(bindgen::callbacks::IntKind::I32);
        } else if name.starts_with("EXC_") || name.starts_with("MACH_PORT_")  || name.starts_with("MACH_MSG_") {
            return Some(bindgen::callbacks::IntKind::U32);
        }

        Some(bindgen::callbacks::IntKind::U64)
    }
}

fn main() {
    let sdkroot_bytes = Command::new("xcrun")
        .arg("--sdk")
        .arg("macosx")
        .arg("--show-sdk-path")
        .output()
        .expect("failed to get sdkroot")
        .stdout;
    let sdkroot = PathBuf::from(String::from_utf8_lossy(&sdkroot_bytes).trim());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    Command::new("mig")
        .current_dir(&out_dir)
        .arg(sdkroot.join("usr/include/mach/mach_exc.defs"))
        .status()
        .expect("failed to run mig");
    
    // Build the mach_excServer library
    cc::Build::new()
        .file(out_dir.join("mach_excServer.c"))
        .compile("mach_excServer");
    
    // And also build bindings for the generated mig header
    bindgen::Builder::default()
        .header(out_dir.join("mach_exc.h").to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate mig bindings")
        .write_to_file(out_dir.join("mach_exc.rs"))
        .expect("Couldn't write mig bindings");

    // Mach headers
    bindgen::Builder::default()
        .header(sdkroot.join("usr/include/mach/mach.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/mach_error.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/mach_init.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/mach_port.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/mach_traps.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/mach_types.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/mach_vm.h").to_str().unwrap())
        .header(sdkroot.join("usr/include/mach/arm/thread_status.h").to_str().unwrap())
        .parse_callbacks(Box::new(MachParseCallbacks))
        .generate()
        .expect("Unable to generate mach bindings")
        .write_to_file(out_dir.join("mach.rs"))
        .expect("Couldn't write mach bindings");

    // DTrace
    bindgen::Builder::default()
        .header(sdkroot.join("usr/include/dtrace.h").to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate dtrace bindings")
        .write_to_file(out_dir.join("dtrace.rs"))
        .expect("Couldn't write dtrace bindings");
    
    println!("cargo:rustc-link-lib=dylib=dtrace");
}
