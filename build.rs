use std::env;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
struct MachParseCallbacks;

static MACRO_PREFIX_TYPES: &[(&str, bindgen::callbacks::IntKind)] = &[
    // N.B. ordering
    ("EXC_MASK_", bindgen::callbacks::IntKind::U32),
    ("EXC_", bindgen::callbacks::IntKind::I32),
    ("KERN_", bindgen::callbacks::IntKind::I32),
    ("MACH_RCV_", bindgen::callbacks::IntKind::I32),
    ("MACH_SEND_", bindgen::callbacks::IntKind::I32),
    ("MACH_NOTIFY_", bindgen::callbacks::IntKind::I32),
    ("THREAD_STATE", bindgen::callbacks::IntKind::I32),
    ("ARM_THREAD_STATE", bindgen::callbacks::IntKind::I32),
    ("EXCEPTION_", bindgen::callbacks::IntKind::U32),
    ("MACH_EXCEPTION_", bindgen::callbacks::IntKind::U32),
    ("MACH_PORT_", bindgen::callbacks::IntKind::U32),
    ("MACH_MSG_", bindgen::callbacks::IntKind::U32),
];

impl bindgen::callbacks::ParseCallbacks for MachParseCallbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
        for &(prefix, kind) in MACRO_PREFIX_TYPES {
            if name.starts_with(prefix) {
                return Some(kind);
            }
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

    // Bindings for the generated mig header
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
        .header(
            sdkroot
                .join("usr/include/mach/mach_error.h")
                .to_str()
                .unwrap(),
        )
        .header(
            sdkroot
                .join("usr/include/mach/mach_init.h")
                .to_str()
                .unwrap(),
        )
        .header(
            sdkroot
                .join("usr/include/mach/mach_port.h")
                .to_str()
                .unwrap(),
        )
        .header(
            sdkroot
                .join("usr/include/mach/mach_traps.h")
                .to_str()
                .unwrap(),
        )
        .header(
            sdkroot
                .join("usr/include/mach/mach_types.h")
                .to_str()
                .unwrap(),
        )
        .header(sdkroot.join("usr/include/mach/mach_vm.h").to_str().unwrap())
        .header(
            sdkroot
                .join("usr/include/mach/arm/thread_status.h")
                .to_str()
                .unwrap(),
        )
        .parse_callbacks(Box::new(MachParseCallbacks))
        .generate()
        .expect("Unable to generate mach bindings")
        .write_to_file(out_dir.join("mach.rs"))
        .expect("Couldn't write mach bindings");

    // Syscall numbers
    bindgen::Builder::default()
        .header(sdkroot.join("usr/include/sys/syscall.h").to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate syscall bindings")
        .write_to_file(out_dir.join("sysno.rs"))
        .expect("Couldn't write syscall bindings");

    // DTrace
    bindgen::Builder::default()
        .header(sdkroot.join("usr/include/dtrace.h").to_str().unwrap())
        .derive_eq(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate dtrace bindings")
        .write_to_file(out_dir.join("dtrace.rs"))
        .expect("Couldn't write dtrace bindings");

    // Recordable protobuf
    prost_build::compile_protos(&["src/recordable/recordable.proto"], &["src/recordable"])
        .expect("Failed to compile recordable.proto");

    println!("cargo:rustc-link-lib=dylib=dtrace");
}
