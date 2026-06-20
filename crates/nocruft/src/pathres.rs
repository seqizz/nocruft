// Path resolution helpers.

use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};

use path_clean::PathClean;

// A creation event captured by the BPF program, plus context snapshotted at
// receive time for later path resolution.
#[derive(Debug, Clone)]
#[allow(dead_code)] // resolve_note is for future verbose-mode debug emission.
pub struct CapturedEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub syscall: u32,
    pub dirfd: i32,
    pub flags: u32,
    pub truncated: bool,
    pub raw_path: String,
    // For relative paths: snapshotted resolution base at event time.
    pub resolved_base: Option<PathBuf>,
    pub resolve_note: Option<String>,
}

pub fn proc_cwd(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{}/cwd", pid)).ok()
}

pub fn cstr_to_string(buf: &[u8]) -> String {
    match CStr::from_bytes_until_nul(buf) {
        Ok(c) => c.to_string_lossy().into_owned(),
        Err(_) => String::from_utf8_lossy(buf).into_owned(),
    }
}

// Join the raw path against the snapshotted base (if relative) and clean it.
// Returns None when the path was relative and we never managed to snapshot a
// base for it.
pub fn resolve(ev: &CapturedEvent) -> Option<PathBuf> {
    let raw = Path::new(&ev.raw_path);
    if raw.is_absolute() {
        return Some(PathBuf::from(&ev.raw_path).clean());
    }
    let base = ev.resolved_base.as_ref()?;
    Some(base.join(raw).clean())
}

// lstat-style existence check.
pub fn exists_now(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

// Return the file's birth time (creation timestamp) in nanoseconds since
// UNIX epoch, if the filesystem supports STATX_BTIME for this inode.
// Returns None if the call fails or btime is unavailable on this fs.
// Uses AT_SYMLINK_NOFOLLOW so a symlinked path returns the symlink's btime,
// not the target's.
pub fn file_btime_unix_ns(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BTIME,
            &mut sx,
        )
    };
    if ret != 0 {
        return None;
    }
    if (sx.stx_mask & libc::STATX_BTIME) == 0 {
        return None;
    }
    Some(sx.stx_btime.tv_sec as u64 * 1_000_000_000 + sx.stx_btime.tv_nsec as u64)
}

pub fn unix_ns_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
