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

    // Syscall numbers
    bindgen::Builder::default()
        .header(sdkroot.join("usr/include/sys/syscall.h").to_str().unwrap())
        .parse_callbacks(Box::new(ParseCallbacks))
        .generate()
        .expect("Unable to generate syscall bindings")
        .write_to_file(out_dir.join("syscall_h.rs"))
        .expect("Couldn't write syscall bindings");

    // Recordable protobuf
    prost_build::compile_protos(&["src/recordable/recordable.proto"], &["."])
        .expect("Failed to compile protos");

    println!("cargo:rustc-link-lib=dylib=dtrace");
}
