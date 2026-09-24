use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "warpspeed-preempt-test-{}-{}",
        std::process::id(),
        nanos
    ))
}

fn warpspeed(args: &[&str]) -> Command {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runner = manifest_dir.join("scripts/codesign-runner.sh");
    let entitlements = manifest_dir.join("warpspeed.entitlements");
    let binary = env!("CARGO_BIN_EXE_warpspeed");

    let mut command = Command::new(runner);
    command
        .env("WARPSPEED_CODESIGN_ENTITLEMENTS", entitlements)
        .arg(binary)
        .args(args);
    command
}

fn build_fixture() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("make")
        .arg("-C")
        .arg(manifest_dir.join("test"))
        .arg("preempt")
        .status()
        .unwrap();
    assert!(status.success(), "failed to build preempt fixture");
    manifest_dir.join("test/preempt")
}

#[track_caller]
fn assert_success(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The fixture's threads race on a counter without syscalls, so its total depends on exactly
/// where they were preempted, which replay has to find again.
#[test]
fn record_and_replay_preemption_match() {
    let fixture = build_fixture();
    let test_dir = unique_test_dir();
    std::fs::create_dir_all(&test_dir).unwrap();
    let trace_path = test_dir.join("preempt.trace");
    let trace_path_str = trace_path.to_str().unwrap();

    let record = warpspeed(&["record", trace_path_str, fixture.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success(&record, "record");
    let record_stdout = String::from_utf8(record.stdout).unwrap();
    assert!(record_stdout.starts_with("counter: "), "{record_stdout}");

    let replay = warpspeed(&["replay", trace_path_str]).output().unwrap();
    assert_success(&replay, "replay");
    assert_eq!(record_stdout, String::from_utf8(replay.stdout).unwrap());

    // Overshooting the first preemption point makes replay start over, which mustn't repeat
    // output.
    let restarted = warpspeed(&["-vvv", "replay", trace_path_str])
        .env("WARPSPEED_TEST_FIRST_ATTEMPT_INSTRUCTIONS_PER_NS", "0.05")
        .output()
        .unwrap();
    assert_success(&restarted, "restarted replay");
    let restarted_stderr = String::from_utf8_lossy(&restarted.stderr);
    assert!(
        restarted_stderr.contains("Restarting replay"),
        "{restarted_stderr}"
    );
    assert_eq!(record_stdout, String::from_utf8(restarted.stdout).unwrap());

    std::fs::remove_dir_all(test_dir).unwrap();
}
