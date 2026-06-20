// Definitions that mirror nocruft.bpf.c on the userspace side. Keep in sync.

pub const PATH_BUF_SZ: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub etype: u32,
    pub pid: u32,
    pub ppid: u32,
    pub dirfd: i32,
    pub flags: u32,
    pub truncated: u32,
    pub result_fd: i32,
    pub _pad: u32,
    pub ts_ns: u64,
    pub path: [u8; PATH_BUF_SZ],
}

pub const EV_FORK_TRACKED: u32 = 1;
pub const EV_EXIT_TRACKED: u32 = 2;
pub const EV_OPENAT_CREATE: u32 = 3;
pub const EV_MKDIRAT: u32 = 4;
pub const EV_RENAMEAT2: u32 = 5;
pub const EV_SYMLINKAT: u32 = 6;
pub const EV_LINKAT: u32 = 7;
pub const EV_CHDIR: u32 = 8;
pub const EV_FCHDIR: u32 = 9;
pub const EV_OPENAT_DIR: u32 = 10;
pub const EV_MKNODAT: u32 = 11;

pub const AT_FDCWD: i32 = -100;

pub fn syscall_name(etype: u32) -> &'static str {
    match etype {
        EV_OPENAT_CREATE => "openat", // open / openat / creat
        EV_MKDIRAT => "mkdir",        // mkdir / mkdirat
        EV_RENAMEAT2 => "renameat",   // rename / renameat / renameat2
        EV_SYMLINKAT => "symlink",    // symlink / symlinkat
        EV_LINKAT => "link",          // link / linkat
        EV_MKNODAT => "mknod",        // mknod / mknodat
        EV_FORK_TRACKED => "fork",
        EV_EXIT_TRACKED => "exit",
        _ => "unknown",
    }
}
