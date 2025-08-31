use std::env;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
// Custom ParseCallbacks which forces all int macros to be u64
struct ParseCallbacks;

impl bindgen::callbacks::ParseCallbacks for ParseCallbacks {
    fn int_macro(&self, _name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
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
        .arg(sdkroot.join("usr/include/mach/mach_vm.defs"))
        .status()
        .expect("Failed to run mig");

    // Bindings for the generated mig header
    bindgen::Builder::default()
        .header(out_dir.join("mach_vm.h").to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate mach_vm mig bindings")
        .write_to_file(out_dir.join("mig__mach_vm_defs.rs"))
        .expect("Couldn't write mach_vm mig bindings");

    // Recordable protobuf
    prost_build::compile_protos(&["src/recordable/recordable.proto"], &["."])
        .expect("Failed to compile protos");

    println!("cargo:rustc-link-lib=dylib=dtrace");
}
