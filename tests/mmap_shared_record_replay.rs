use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "warpspeed-mmap-shared-test-{}-{}",
        std::process::id(),
        nanos
    ))
}

fn run_warpspeed(args: &[&str]) -> std::process::Output {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runner = manifest_dir.join("scripts/codesign-runner.sh");
    let entitlements = manifest_dir.join("warpspeed.entitlements");
    let binary = env!("CARGO_BIN_EXE_warpspeed");

    Command::new(runner)
        .env("WARPSPEED_CODESIGN_ENTITLEMENTS", entitlements)
        .arg(binary)
        .args(args)
        .output()
        .unwrap()
}

fn build_fixture() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("make")
        .arg("-C")
        .arg(manifest_dir.join("test"))
        .arg("mmap_shared")
        .status()
        .unwrap();
    assert!(status.success(), "failed to build mmap_shared fixture");
    manifest_dir.join("test/mmap_shared")
}

#[test]
fn record_and_replay_mmap_shared_match() {
    let fixture = build_fixture();
    let test_dir = unique_test_dir();
    std::fs::create_dir_all(&test_dir).unwrap();

    let backing_path = test_dir.join("backing.bin");
    let trace_path = test_dir.join("mmap_shared.trace");
    std::fs::write(&backing_path, b"abcde").unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&backing_path)
        .unwrap();
    file.set_len(0x1000).unwrap();

    let fixture_path = fixture.to_str().unwrap();
    let backing_path_str = backing_path.to_str().unwrap();
    let trace_path_str = trace_path.to_str().unwrap();

    let record = run_warpspeed(&["record", trace_path_str, fixture_path, backing_path_str]);
    assert!(
        record.status.success(),
        "record failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        record.status,
        String::from_utf8_lossy(&record.stdout),
        String::from_utf8_lossy(&record.stderr)
    );

    std::fs::write(&backing_path, b"vwxyz").unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&backing_path)
        .unwrap();
    file.set_len(0x1000).unwrap();

    let replay = run_warpspeed(&["replay", trace_path_str]);
    assert!(
        replay.status.success(),
        "replay failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        replay.status,
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );

    let record_stdout = String::from_utf8(record.stdout).unwrap();
    let replay_stdout = String::from_utf8(replay.stdout).unwrap();

    assert_eq!(record_stdout, "initial:abcde\nmapped:XYcde\nfile:XYcde\n");
    assert_eq!(record_stdout, replay_stdout, "replay output differed");

    std::fs::remove_dir_all(test_dir).unwrap();
}
