use std::process::Command;
use std::path::PathBuf;
use std::env;

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
