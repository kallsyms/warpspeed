use anyhow::{Context, Result};
use nix::sys::stat::fstat;
use nix::unistd::dup2;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::recordable;

#[derive(Clone, Debug)]
pub struct FdState {
    pub path: String,
    pub device: u64,
    pub inode: u64,
    pub writable: bool,
    pub is_regular: bool,
}

impl FdState {
    pub fn from_fd(fd: i32) -> Result<Self> {
        let stat = fstat(fd).with_context(|| format!("fstat failed for fd {}", fd))?;
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("fcntl(F_GETFL) failed for fd {}", fd));
        }

        Ok(Self {
            path: path_for_fd(fd).unwrap_or_default(),
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            writable: (flags & nix::libc::O_ACCMODE) != nix::libc::O_RDONLY,
            is_regular: (stat.st_mode & nix::libc::S_IFMT) == nix::libc::S_IFREG,
        })
    }
}

pub struct ShadowFile {
    pub path: PathBuf,
    file: File,
}

impl ShadowFile {
    pub fn from_snapshot(shared_file: &recordable::trace::SharedFile) -> Result<Self> {
        let path = unique_shadow_path(shared_file.id);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("failed to create shadow file at {}", path.display()))?;

        file.write_all(&shared_file.initial_contents).with_context(|| {
            format!(
                "failed to initialize shadow file for shared file {}",
                shared_file.id
            )
        })?;
        file.flush()?;

        Ok(Self { path, file })
    }

    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

pub fn read_fd_contents(fd: i32, size: usize) -> Result<Vec<u8>> {
    let mut contents = vec![0; size];
    let mut offset = 0usize;

    while offset < contents.len() {
        let ret = unsafe {
            nix::libc::pread(
                fd,
                contents[offset..].as_mut_ptr() as *mut nix::libc::c_void,
                contents.len() - offset,
                offset as nix::libc::off_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("pread failed for fd {}", fd));
        }
        if ret == 0 {
            contents.truncate(offset);
            break;
        }
        offset += ret as usize;
    }

    Ok(contents)
}

pub fn rebind_fd(fd: i32, shadow_fd: RawFd) -> Result<()> {
    dup2(shadow_fd, fd).with_context(|| format!("dup2({}, {}) failed", shadow_fd, fd))?;
    Ok(())
}

fn path_for_fd(fd: i32) -> Result<String> {
    let mut buf = [0u8; nix::libc::PATH_MAX as usize];
    let ret = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETPATH, buf.as_mut_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fcntl(F_GETPATH) failed for fd {}", fd));
    }

    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
}

fn unique_shadow_path(shared_file_id: u64) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "warpspeed-shared-file-{}-{}-{}",
        std::process::id(),
        shared_file_id,
        nanos
    ))
}
