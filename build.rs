use std::env;
use std::path::PathBuf;
use std::process::Command;

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

    // Mach trap numbers
    bindgen::Builder::default()
        .header(
            sdkroot
                .join("usr/include/mach/mach_traps.h")
                .to_str()
                .unwrap(),
        )
        .generate()
        .expect("Unable to generate mach bindings")
        .write_to_file(out_dir.join("mach_traps_h.rs"))
        .expect("Couldn't write mach bindings");

    // Syscall numbers
    bindgen::Builder::default()
        .header(sdkroot.join("usr/include/sys/syscall.h").to_str().unwrap())
        .generate()
        .expect("Unable to generate syscall bindings")
        .write_to_file(out_dir.join("syscall_h.rs"))
        .expect("Couldn't write syscall bindings");

    // Recordable protobuf
    prost_build::compile_protos(&["src/recordable/recordable.proto"], &["."])
        .expect("Failed to compile protos");

    println!("cargo:rustc-link-lib=dylib=dtrace");
}
