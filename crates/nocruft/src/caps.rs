// Pre-flight check that we have the capabilities to load BPF tracepoint
// programs. On kernels >= 5.8 the canonical set is CAP_BPF + CAP_PERFMON;
// older kernels (and some configurations) accept CAP_SYS_ADMIN as a
// catch-all. We read /proc/self/status to avoid pulling in a caps crate.

use anyhow::{bail, Context, Result};
use std::path::Path;

const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

pub fn check_bpf_privileges() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;

    let cap_eff: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:\t"))
        .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
        .unwrap_or(0);

    let has = |bit: u32| (cap_eff >> bit) & 1 == 1;

    if has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON)) {
        return Ok(());
    }

    bail!(
        "insufficient privileges to load BPF programs.\n\
         \n\
         nocruft needs CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN as a fallback).\n\
         Detected effective caps: CAP_BPF={} CAP_PERFMON={} CAP_SYS_ADMIN={}.\n\
         \n\
         Fix one of:\n  \
           - NixOS:  add the flake module and `programs.nocruft.enable = true;`\n  \
                     then run `nocruft` (already at /run/wrappers/bin/nocruft).\n  \
           - setcap: sudo setcap cap_bpf,cap_perfmon+ep $(realpath $(command -v nocruft))\n  \
           - sudo:   sudo -E nocruft ...",
        bool_int(has(CAP_BPF)),
        bool_int(has(CAP_PERFMON)),
        bool_int(has(CAP_SYS_ADMIN)),
    );
}

fn bool_int(b: bool) -> u8 {
    if b {
        1
    } else {
        0
    }
}

// CO-RE relocations in the BPF program need the running kernel's BTF info.
// On kernels without CONFIG_DEBUG_INFO_BTF the file is missing and load
// will fail later with a confusing message; we'd rather complain up front.
pub fn check_kernel_btf() -> Result<()> {
    let p = Path::new("/sys/kernel/btf/vmlinux");
    if !p.exists() {
        bail!(
            "kernel BTF info not available at {}.\n\
             \n\
             nocruft uses CO-RE BPF programs which require the running\n\
             kernel to expose its type info there. Recent NixOS, Debian\n\
             bookworm+, Fedora 38+, etc. ship with CONFIG_DEBUG_INFO_BTF=y\n\
             by default. If you built your own kernel, enable it and\n\
             rebuild.",
            p.display()
        );
    }
    Ok(())
}
