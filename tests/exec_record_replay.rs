use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "warpspeed-exec-test-{}-{}",
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
        .arg("exec")
        .status()
        .unwrap();
    assert!(status.success(), "failed to build exec fixture");
    manifest_dir.join("test/exec")
}

/// The fixture execs itself, which must happen on replay too, closing its close-on-exec fd.
#[test]
fn record_and_replay_exec_match() {
    let fixture = build_fixture();
    let test_dir = unique_test_dir();
    std::fs::create_dir_all(&test_dir).unwrap();
    let trace_path = test_dir.join("exec.trace");
    let trace_path_str = trace_path.to_str().unwrap();

    let record = run_warpspeed(&["record", trace_path_str, fixture.to_str().unwrap()]);
    assert!(
        record.status.success(),
        "record failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        record.status,
        String::from_utf8_lossy(&record.stdout),
        String::from_utf8_lossy(&record.stderr)
    );

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
    assert_eq!(record_stdout, "before exec\nafter exec: fd closed\n");
    assert_eq!(record_stdout, replay_stdout, "replay output differed");
    let replay_stderr = String::from_utf8_lossy(&replay.stderr);
    assert!(!replay_stderr.contains("mismatch"), "{replay_stderr}");

    std::fs::remove_dir_all(test_dir).unwrap();
}
