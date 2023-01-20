use std::process::Command;

fn main() {
    let sdkroot = Command::new("xcrun")
        .arg("--sdk")
        .arg("macosx")
        .arg("--show-sdk-path")
        .output()
        .expect("failed to get sdkroot")
        .stdout;

    Command::new("mig")
        .arg(format!(
            "{}/usr/include/mach/mach_exc.defs",
            String::from_utf8_lossy(&sdkroot)
        ))
        .output()
        .expect("failed to run mig");

    cc::Build::new()
        .file("mach_excServer.c")
        .compile("mach_excServer");
}