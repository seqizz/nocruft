mod bpf_events;
mod caps;
mod cli;
mod output;
mod pathres;

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};
use path_clean::PathClean;
use tracing::{debug, warn};

use crate::bpf_events::{
    syscall_name, Event, AT_FDCWD, EV_CHDIR, EV_EXIT_TRACKED, EV_FCHDIR, EV_FORK_TRACKED,
    EV_LINKAT, EV_MKDIRAT, EV_MKNODAT, EV_OPENAT_CREATE, EV_OPENAT_DIR, EV_RENAMEAT2, EV_SYMLINKAT,
};
use crate::pathres::{cstr_to_string, proc_cwd, unix_ns_now, CapturedEvent};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/nocruft.skel.rs"));
}

use skel::*;

// Hard upper bound on captured events. Long-running interactive sessions
// that scribble heavily can otherwise grow the Vec unbounded. Once hit,
// further events are dropped and a single warning is logged.
const MAX_EVENTS: usize = 100_000;

struct State {
    events: Vec<CapturedEvent>,
    overflow_warned: bool,
    // pid -> current cwd. Authoritative; built from ordered fork/chdir/fchdir
    // events and the initial root seed via /proc.
    cwd_cache: HashMap<u32, std::path::PathBuf>,
    // pid -> (fd -> absolute path of directory opened). Built from
    // O_DIRECTORY openat events. Used to resolve fchdir(fd).
    fd_map: HashMap<u32, HashMap<i32, std::path::PathBuf>>,
}

impl State {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            overflow_warned: false,
            cwd_cache: HashMap::new(),
            fd_map: HashMap::new(),
        }
    }

    fn push_event(&mut self, ev: CapturedEvent) {
        if self.events.len() >= MAX_EVENTS {
            if !self.overflow_warned {
                warn!(
                    "captured {} events; dropping subsequent ones. Re-run with \
                     a more targeted command to stay under the cap.",
                    MAX_EVENTS
                );
                self.overflow_warned = true;
            }
            return;
        }
        self.events.push(ev);
    }
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = cli::parse_argv(argv).context("parse argv")?;

    init_logging(parsed.flags.verbose);

    // Fail with a friendly message BEFORE libbpf gets a chance to print its
    // own -EPERM noise. Detects the common "ran without setcap/sudo" case.
    caps::check_bpf_privileges()?;
    // And before CO-RE relocation fails on a kernel that doesn't expose BTF.
    caps::check_kernel_btf()?;

    // Capture wall-clock start time BEFORE attaching BPF; used to filter out
    // O_CREAT opens of pre-existing files (modified, not created).
    let start_unix_ns = unix_ns_now();

    let _ = bump_memlock_rlimit();

    debug!("loading BPF skeleton");
    let skel_builder = NocruftSkelBuilder::default();
    let mut obj_storage: MaybeUninit<OpenObject> = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut obj_storage)
        .context("open BPF skeleton")?;
    let mut skel = open_skel.load().context("load BPF skeleton")?;
    skel.attach().context("attach BPF programs")?;
    debug!("BPF programs attached");

    let state = Arc::new(Mutex::new(State::new()));
    let cb_state = state.clone();

    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();
    rb_builder
        .add(&skel.maps.events, move |data: &[u8]| {
            handle_event(data, &cb_state);
            0
        })
        .context("attach ringbuf consumer")?;
    let rb = rb_builder.build().context("build ringbuf")?;

    debug!(
        "spawning {} with args {:?}",
        parsed.child_prog, parsed.child_args
    );

    // Ignore SIGINT/SIGQUIT in nocruft so Ctrl-C delivered to the foreground
    // process group reaches the child shell only. The child resets these to
    // default in pre_exec so it (e.g. bash) handles them normally. Without
    // this, Ctrl-C inside an interactive nix-shell would kill nocruft too
    // and we'd lose the summary.
    //
    // Use sigaction rather than signal(2): the latter's semantics differ
    // across libc implementations (SysV vs BSD, with/without SA_RESTART).
    set_signal(libc::SIGINT, libc::SIG_IGN);
    set_signal(libc::SIGQUIT, libc::SIG_IGN);

    let mut cmd = Command::new(&parsed.child_prog);
    cmd.args(&parsed.child_args);
    unsafe {
        cmd.pre_exec(|| {
            set_signal(libc::SIGINT, libc::SIG_DFL);
            set_signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {} {:?}", parsed.child_prog, parsed.child_args))?;
    let root_pid: u32 = child.id();
    debug!("spawned root pid={}", root_pid);

    if let Some(cwd) = proc_cwd(root_pid) {
        state.lock().unwrap().cwd_cache.insert(root_pid, cwd);
    }

    let key = root_pid.to_ne_bytes();
    let val: [u8; 1] = [1];
    skel.maps
        .tracked_pids
        .update(&key, &val, MapFlags::ANY)
        .context("seed tracked_pids with root pid")?;

    loop {
        rb.poll(Duration::from_millis(100)).ok();
        if let Some(status) = child.try_wait().context("try_wait")? {
            debug!("root child exited: {:?}", status);
            break;
        }
    }
    for _ in 0..5 {
        rb.poll(Duration::from_millis(50)).ok();
    }

    let st = state.lock().unwrap();
    output::emit(&st.events, &parsed.flags, start_unix_ns, &parsed.patterns);

    Ok(())
}

fn init_logging(verbose: bool) {
    let default_filter = if verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .init();
}

fn handle_event(data: &[u8], state: &Arc<Mutex<State>>) {
    if data.len() < std::mem::size_of::<Event>() {
        warn!("short event: {} bytes", data.len());
        return;
    }
    let ev: Event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };

    let mut st = state.lock().unwrap();

    match ev.etype {
        EV_FORK_TRACKED => {
            debug!("fork  pid={} parent={}", ev.pid, ev.ppid);
            // Child inherits parent's cwd. Prefer the value we already track
            // (authoritative); fall back to /proc only if we don't know
            // parent's cwd (e.g. fork happens before we seed).
            let parent_cwd = st.cwd_cache.get(&ev.ppid).cloned();
            let cwd = parent_cwd.or_else(|| proc_cwd(ev.pid));
            if let Some(c) = cwd {
                st.cwd_cache.insert(ev.pid, c);
            }
        }
        EV_EXIT_TRACKED => {
            debug!("exit  pid={}", ev.pid);
            st.cwd_cache.remove(&ev.pid);
            st.fd_map.remove(&ev.pid);
        }
        EV_CHDIR => {
            let raw = cstr_to_string(&ev.path);
            let new_cwd = if raw.starts_with('/') {
                Some(std::path::PathBuf::from(&raw).clean())
            } else {
                // Join relative path against the known cwd. If we don't know
                // it, last-ditch /proc readlink (which is now at the *new*
                // cwd because chdir already returned).
                let base = st
                    .cwd_cache
                    .get(&ev.pid)
                    .cloned()
                    .or_else(|| proc_cwd(ev.pid));
                base.map(|b| b.join(&raw).clean())
            };
            if let Some(c) = new_cwd {
                debug!("chdir pid={} -> {}", ev.pid, c.display());
                st.cwd_cache.insert(ev.pid, c);
            } else {
                warn!("chdir pid={} raw={:?}: no base cwd known", ev.pid, raw);
            }
        }
        EV_FCHDIR => {
            // Prefer our fd_map (populated by ordered EV_OPENAT_DIR events,
            // race-free). Fall back to /proc only if we don't have the
            // mapping (e.g. fd inherited from parent or opened before we
            // started tracking).
            let resolved = st
                .fd_map
                .get(&ev.pid)
                .and_then(|m| m.get(&ev.dirfd).cloned());
            let final_path = resolved.or_else(|| {
                let link = format!("/proc/{}/fd/{}", ev.pid, ev.dirfd);
                std::fs::read_link(&link).ok()
            });
            match final_path {
                Some(p) => {
                    debug!("fchdir pid={} fd={} -> {}", ev.pid, ev.dirfd, p.display());
                    st.cwd_cache.insert(ev.pid, p);
                }
                None => {
                    warn!(
                        "fchdir pid={} fd={}: no mapping and /proc readlink failed",
                        ev.pid, ev.dirfd
                    );
                }
            }
        }
        EV_OPENAT_DIR => {
            // Resolve the openat's path to an absolute host path, using the
            // current cwd state, then record fd -> path so subsequent
            // fchdir(fd) by the same pid can be resolved.
            let raw_path = cstr_to_string(&ev.path);
            let abs: Option<std::path::PathBuf> = if raw_path.starts_with('/') {
                Some(std::path::PathBuf::from(&raw_path).clean())
            } else if ev.dirfd == AT_FDCWD {
                st.cwd_cache
                    .get(&ev.pid)
                    .cloned()
                    .or_else(|| proc_cwd(ev.pid))
                    .map(|b| b.join(&raw_path).clean())
            } else if ev.dirfd >= 0 {
                // openat with a dir-relative dirfd. Try fd_map for that dirfd
                // first, fall back to /proc.
                let base = st
                    .fd_map
                    .get(&ev.pid)
                    .and_then(|m| m.get(&ev.dirfd).cloned())
                    .or_else(|| {
                        std::fs::read_link(format!("/proc/{}/fd/{}", ev.pid, ev.dirfd)).ok()
                    });
                base.map(|b| b.join(&raw_path).clean())
            } else {
                None
            };
            match abs {
                Some(p) => {
                    debug!(
                        "openat-dir pid={} fd={} -> {}",
                        ev.pid,
                        ev.result_fd,
                        p.display()
                    );
                    st.fd_map.entry(ev.pid).or_default().insert(ev.result_fd, p);
                }
                None => {
                    debug!(
                        "openat-dir pid={} fd={} raw={:?}: could not resolve",
                        ev.pid, ev.result_fd, raw_path
                    );
                }
            }
        }
        EV_OPENAT_CREATE | EV_MKDIRAT | EV_RENAMEAT2 | EV_SYMLINKAT | EV_LINKAT | EV_MKNODAT => {
            let raw_path = cstr_to_string(&ev.path);

            let mut resolved_base = None;
            let mut resolve_note = None;

            if !raw_path.starts_with('/') {
                if ev.dirfd == AT_FDCWD {
                    if let Some(c) = st.cwd_cache.get(&ev.pid).cloned() {
                        resolved_base = Some(c);
                    } else if let Some(c) = proc_cwd(ev.pid) {
                        // Should be rare: we missed the fork or root seed.
                        st.cwd_cache.insert(ev.pid, c.clone());
                        resolved_base = Some(c);
                    } else {
                        resolve_note = Some(format!("cwd for pid {} not known", ev.pid));
                    }
                } else if ev.dirfd >= 0 {
                    let link = format!("/proc/{}/fd/{}", ev.pid, ev.dirfd);
                    match std::fs::read_link(&link) {
                        Ok(p) => resolved_base = Some(p),
                        Err(e) => {
                            resolve_note = Some(format!("readlink {} failed: {}", link, e));
                        }
                    }
                } else {
                    resolve_note = Some(format!("unrecognized dirfd {}", ev.dirfd));
                }
            }

            debug!(
                "{} pid={} dirfd={} flags=0x{:x} raw={:?} base={:?}",
                syscall_name(ev.etype),
                ev.pid,
                ev.dirfd,
                ev.flags,
                raw_path,
                resolved_base.as_ref().map(|p| p.display().to_string()),
            );

            st.push_event(CapturedEvent {
                ts_ns: ev.ts_ns,
                pid: ev.pid,
                syscall: ev.etype,
                dirfd: ev.dirfd,
                flags: ev.flags,
                truncated: ev.truncated != 0,
                raw_path,
                resolved_base,
                resolve_note,
            });
        }
        other => warn!("unknown event type {}", other),
    }
}

fn set_signal(signum: libc::c_int, handler: libc::sighandler_t) {
    // Portable signal handling: build a sigaction struct, leave sa_mask
    // empty and sa_flags=0 (default semantics, no SA_RESTART surprises).
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(signum, &sa, std::ptr::null_mut());
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        anyhow::bail!("setrlimit(RLIMIT_MEMLOCK) failed");
    }
    Ok(())
}
