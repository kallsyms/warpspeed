use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("warpspeed-date-test-{}-{}", std::process::id(), nanos))
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

#[test]
fn record_and_replay_date_match() {
    let test_dir = unique_test_dir();
    std::fs::create_dir_all(&test_dir).unwrap();
    let trace_path = test_dir.join("date.trace");
    let trace_path_str = trace_path.to_str().unwrap();

    let record = run_warpspeed(&["record", trace_path_str, "/bin/date"]);
    assert!(
        record.status.success(),
        "record failed: status={:?}\nstderr:\n{}",
        record.status,
        String::from_utf8_lossy(&record.stderr)
    );

    let replay = run_warpspeed(&["replay", trace_path_str]);
    assert!(
        replay.status.success(),
        "replay failed: status={:?}\nstderr:\n{}",
        replay.status,
        String::from_utf8_lossy(&replay.stderr)
    );

    let record_stdout = String::from_utf8(record.stdout).unwrap();
    let replay_stdout = String::from_utf8(replay.stdout).unwrap();

    assert!(!record_stdout.is_empty(), "record stdout was empty");
    assert_eq!(record_stdout, replay_stdout, "replay output differed");

    std::fs::remove_dir_all(test_dir).unwrap();
}
