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

    bindgen::Builder::default()
        .header("../loader.h")
        .header("../shared_cache.h")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("loader_ffi.rs"))
        .unwrap();

    cc::Build::new()
        .file("../loader.c")
        .file("../commpage.c")
        .file("../shared_cache.c")
        .include(sdkroot.join("usr/local/include/"))
        .compile("loader_ffi");
}
