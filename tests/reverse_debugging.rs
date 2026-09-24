//! Debugging a replay forwards and backwards, as a GDB client (speaking the remote protocol
//! directly, since there may be no GDB around).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "warpspeed-reverse-test-{}-{}",
        std::process::id(),
        nanos
    ))
}

fn warpspeed(args: &[&str]) -> Command {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(manifest_dir.join("scripts/codesign-runner.sh"));
    command
        .env(
            "WARPSPEED_CODESIGN_ENTITLEMENTS",
            manifest_dir.join("warpspeed.entitlements"),
        )
        .arg(env!("CARGO_BIN_EXE_warpspeed"))
        .args(args);
    command
}

fn build_fixture() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("make")
        .arg("-C")
        .arg(manifest_dir.join("test"))
        .arg("reverse")
        .status()
        .unwrap();
    assert!(status.success(), "failed to build reverse fixture");
    manifest_dir.join("test/reverse")
}

struct Gdb {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Gdb {
    fn connect(port: u16) -> Self {
        let deadline = Instant::now() + Duration::from_secs(60);
        let stream = loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(err) => panic!("connecting to the replay: {err}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .unwrap();
        let mut gdb = Self {
            stream,
            buffer: Vec::new(),
        };
        // Like GDB, which acknowledges the (implicit) connection first.
        gdb.stream.write_all(b"+").unwrap();
        assert_eq!(gdb.request("QStartNoAckMode"), "OK");
        gdb
    }

    fn send(&mut self, packet: &str) {
        let checksum = packet.bytes().fold(0u8, |sum, b| sum.wrapping_add(b));
        self.stream
            .write_all(format!("${packet}#{checksum:02x}").as_bytes())
            .unwrap();
    }

    fn recv(&mut self) -> String {
        loop {
            // Skip acknowledgements.
            while matches!(self.buffer.first(), Some(b'+' | b'-')) {
                self.buffer.remove(0);
            }
            if let Some(end) = self.buffer.iter().position(|&b| b == b'#') {
                if self.buffer.len() >= end + 3 {
                    assert_eq!(self.buffer[0], b'$', "{:?}", String::from_utf8_lossy(&self.buffer));
                    let packet = String::from_utf8(self.buffer[1..end].to_vec()).unwrap();
                    self.buffer.drain(..end + 3);
                    self.stream.write_all(b"+").unwrap();
                    return packet;
                }
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).expect("reading from the replay");
            assert!(n > 0, "the replay hung up");
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    fn request(&mut self, packet: &str) -> String {
        self.send(packet);
        self.recv()
    }

    fn read_u64(&mut self, addr: u64) -> u64 {
        let hex = self.request(&format!("m{addr:x},8"));
        let bytes: Vec<u8> = (0..8)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn register(&mut self, index: usize) -> u64 {
        let hex = self.request(&format!("p{index:x}"));
        let bytes: Vec<u8> = (0..8)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
}

struct Replay(Child);

impl Drop for Replay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn parse_addresses(stdout: &str) -> (u64, u64) {
    let line = stdout.lines().next().unwrap();
    let field = |name: &str| {
        let start = line.find(&format!("{name}=0x")).unwrap() + name.len() + 3;
        let hex: String = line[start..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        u64::from_str_radix(&hex, 16).unwrap()
    };
    (field("value"), field("set_value"))
}

#[test]
fn reverse_continue_to_watchpoints_and_breakpoints() {
    let fixture = build_fixture();
    let test_dir = unique_test_dir();
    std::fs::create_dir_all(&test_dir).unwrap();
    let trace_path = test_dir.join("reverse.trace");
    let trace = trace_path.to_str().unwrap();

    let record = warpspeed(&["record", trace, fixture.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&record.stdout);
    assert!(record.status.success(), "record failed:\n{stdout}\n{}", String::from_utf8_lossy(&record.stderr));
    let (value, set_value) = parse_addresses(&stdout);

    let port = free_port();
    let _replay = Replay(
        warpspeed(&["replay", trace, "--gdb-port", &port.to_string()])
            // Several checkpoints, so going backwards has to look through more than one.
            .env("WARPSPEED_CHECKPOINT_EVERY", "10000000")
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut gdb = Gdb::connect(port);

    // Watching writes to `value`, forwards...
    assert_eq!(gdb.request(&format!("Z2,{value:x},8")), "OK");
    for expected in 1..=3 {
        let stop = gdb.request("c");
        assert!(stop.starts_with("T05watch:"), "{stop}");
        assert_eq!(gdb.read_u64(value), expected);
    }
    // ...and backwards, to each earlier write, then the start.
    for expected in [2, 1] {
        let stop = gdb.request("bc");
        assert!(stop.starts_with("T05watch:"), "{stop}");
        assert_eq!(gdb.read_u64(value), expected);
    }
    assert_eq!(gdb.request("bc"), "T05replaylog:begin;");
    assert_eq!(gdb.read_u64(value), 0);
    // And forwards again from there.
    assert!(gdb.request("c").starts_with("T05watch:"));
    assert_eq!(gdb.read_u64(value), 1);

    // A breakpoint on set_value, whose argument is in x0.
    assert_eq!(gdb.request(&format!("z2,{value:x},8")), "OK");
    assert_eq!(gdb.request(&format!("Z0,{set_value:x},4")), "OK");
    assert_eq!(gdb.request("c"), "S05");
    assert_eq!(gdb.register(32), set_value);
    assert_eq!(gdb.register(0), 2);
    assert_eq!(gdb.request("bc"), "S05");
    assert_eq!(gdb.register(0), 1);
    for expected in 2..=5 {
        assert_eq!(gdb.request("c"), "S05");
        assert_eq!(gdb.register(0), expected);
    }
    assert_eq!(gdb.request("c"), "W00");

    // Which has no reply.
    gdb.send("k");
    std::fs::remove_dir_all(test_dir).unwrap();
}
