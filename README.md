# nocruft

Trace (and remove) filesystem creations under `nix-shell` or any child process via eBPF.

`nocruft -p hello` opens a `nix-shell -p hello`, lets all writes persist
normally, and when the shell exits prints the paths that the shell or any of
its descendants created. No overlay, no chroot, no `strace`. Reads come from
the kernel via tracepoints with negligible overhead.

```
$ nocruft -p hello
[nix-shell:~]$ mkdir /tmp/zonk
[nix-shell:~]$ touch /tmp/zonk/a /tmp/zonk/b
[nix-shell:~]$ exit

=== created paths (3) ===
/tmp/zonk
/tmp/zonk/a
/tmp/zonk/b
```

## Why

`nix-shell` is great for trying things, but tools leave junk all over your
home: `~/.config/foo`, `~/.cache/bar`, `/tmp/something`. nocruft tells you
exactly which paths the shell touched so you can clean up confidently.

## Status

x86_64 Linux only, kernel ≥ 5.8 (needs BPF ring buffer + BTF). Works on
NixOS and recent Debian.

## Quickstart

```sh
nix develop                                       # gets clang, libbpf, rustc
cargo build --release
sudo setcap cap_bpf,cap_perfmon+ep ./target/release/nocruft

./target/release/nocruft -p hello
```

If `setcap` isn't an option (the binary lives in `/nix/store` which is
immutable; copy it out, or just run with sudo):

```sh
sudo -E ./target/release/nocruft -p hello
```

The `-E` is important so `$HOME`, `$NIX_PATH`, etc. survive to `nix-shell`.

## CLI

Anything not starting with `--nc-` is passed through to `nix-shell`:

```sh
nocruft -p hello                          # nix-shell -p hello
nocruft -- shell.nix                      # nix-shell -- shell.nix
nocruft -p python3 --run 'python -c ...'  # nix-shell -p python3 --run ...
```

`--nc-*` flags (none, or any combination, can precede the nix-shell args):

| Flag                      | Default | Effect |
| ------------------------- | ------- | ------ |
| `--nc-json`               | off     | Emit JSON Lines instead of the plain summary. One record per kept event. |
| `--nc-no-dedupe`          | off     | Print every event in arrival order with metadata, not a deduped summary. |
| `--nc-include-deleted`    | off     | Keep paths that no longer exist on disk. |
| `--nc-include-modified`   | off     | Keep `O_CREAT` opens of files that already existed (i.e. modifications). |
| `--nc-include-system`     | off     | Keep paths under `/dev`, `/proc`, `/sys`, `/run`, `/tmp/.X*-unix`, `/var/run`. |
| `--nc-include-history`    | off     | Keep shell/REPL history files (`.bash_history`, `.zsh_history`, …). |
| `--nc-include-build`      | off     | Keep build artifacts (`.git`, `node_modules`, `__pycache__`, cargo `target/{debug,release}`, `*.pyc`, …). |
| `--nc-exclude GLOB`       | —       | Drop paths matching this glob. Repeatable. Use `**` to span slashes. |
| `--nc-include GLOB`       | —       | Force-keep paths matching this glob, overriding all defaults and excludes. Repeatable. |
| `--nc-delete-interactive` | off     | After the summary, show a multi-select prompt; selected paths are deleted (deepest-first). |
| `--nc-dry-run-delete`     | off     | Prefix output with `would delete: ` (no actual deletion). |
| `--nc-verbose`            | off     | Debug-level logging to stderr. |
| `--nc-exec PROG`          | —       | Run `PROG` instead of `nix-shell`. Debug aid. |

Flag parsing rule: tokens beginning with `--nc-` go to nocruft; everything
else (including `-p`, `--pure`, `shell.nix`, and even a bare `--`) is passed
to nix-shell verbatim. The `--nc-*` prefix exists precisely to avoid
collisions with nix-shell's flags (`nix-shell` has its own `--verbose`,
`--run`, etc.).

## What gets traced

Successful creation-like syscalls executed by any process in the spawned
tree:

| Syscall family   | Members | Notes |
| ---------------- | ------- | ----- |
| openat O_CREAT   | `open`, `openat`, `openat2`, `creat` | The file's `stx_btime` is compared to nocruft start time to filter out modifications of pre-existing files. |
| mkdir            | `mkdir`, `mkdirat` | |
| rename           | `rename`, `renameat`, `renameat2` | Destination side. `RENAME_EXCHANGE` is not specially handled. |
| symlink          | `symlink`, `symlinkat` | The new symlink path (target is not traced). |
| link             | `link`, `linkat` | The new hard link path. |
| mknod            | `mknod`, `mknodat` | Special files (fifos, char/block devices). |

Plus, for cwd tracking, the tool also traces `chdir`, `fchdir`, and
directory opens (`openat`/`openat2` with `O_DIRECTORY`) — these never appear
in the summary, but they make sure paths from inside processes that chdir
mid-execution (`mkdir -p A/B/C` is the canonical case) resolve correctly.

## How it works (1-minute version)

1. A small C BPF program (compiled via `libbpf-cargo` + `clang -target bpf`)
   attaches tracepoints to the syscalls above plus
   `sched_process_fork`/`sched_process_exit`.
2. A BPF hash map (`tracked_pids`) is seeded with the spawned shell's pid;
   the fork tracepoint propagates the flag to descendants, exit removes them.
3. Successful creation events are pushed to a BPF ring buffer with the
   relative path string and any dirfd.
4. Userspace consumes the ring buffer, maintains per-pid cwd state (driven
   by ordered `chdir`/`fchdir` events plus a `fd → path` map seeded by
   `O_DIRECTORY` opens), resolves each event to an absolute host path, then
   applies the filters and prints the summary.

## Limitations

- The "did this file exist before nocruft started?" check uses `statx`
  `STATX_BTIME`. Atomic-save patterns (write to temp + `rename`) reset btime,
  so files like `~/.zhistory` look freshly created. Mitigated by the
  history-file blocklist; works around the rest via `--nc-include-modified`
  / `--nc-exclude`.
- Path buffer is 256 bytes; longer paths are flagged truncated and may
  appear as relative entries that fail to resolve.
- Mount namespaces / chroot inside the shell produce paths that may not
  match the host view of the filesystem.
- `dirfd`-based syscalls on directories opened *before* nocruft started
  tracking (e.g. inherited fds) cannot have their dirfd resolved; falls back
  to `/proc/<pid>/fd/<dirfd>` readlink which is racy if the fd is closed
  fast.
- Records syscalls executed by the tracked process tree, not semantic
  ownership. A file passed to the shell by an external process and then
  modified by the shell still counts as "created in the tree" only if the
  shell itself created it.
- `renameat2` with `RENAME_EXCHANGE` swaps two paths. Neither is strictly
  "created", yet the destination is reported. Rare outside editors doing
  crash-safe writes (and there the modified-vs-created filter handles it),
  but if your workload does it often, use `--nc-exclude`.
- The tool does **not** prevent writes. Cleanup happens after the fact via
  `--nc-delete-interactive` or by hand.

## Installing on NixOS via flake

In your system flake's `inputs`:

```nix
inputs.nocruft.url = "path:/devel/nocruft"; # or github:user/nocruft
```

In your `nixosConfiguration` modules:

```nix
{ inputs, ... }: {
  imports = [ inputs.nocruft.nixosModules.default ];
  programs.nocruft.enable = true;
}
```

After `nixos-rebuild switch`, the binary is at `/run/wrappers/bin/nocruft`
with `cap_bpf,cap_perfmon+ep` already applied via NixOS' `security.wrappers`
mechanism (the only NixOS-clean way to ship a capability-bearing binary,
since the Nix store itself can't carry caps). Just run `nocruft -p hello`.

## Permissions

eBPF tracepoint programs need `CAP_BPF` + `CAP_PERFMON` on kernels ≥ 5.8.
The order of preference:

1. `setcap cap_bpf,cap_perfmon+ep $(realpath nocruft)` — best UX, run as
   yourself, `$HOME` and `$NIX_PATH` are yours.
2. `sudo -E nocruft …` — works everywhere but emits the `$HOME is not owned
   by you` warning and runs `nix-shell` as root.
3. `sudo nocruft …` — last resort; loses your environment, often confuses
   `nix-shell`.

## Tests

Integration tests live in `crates/nocruft/tests/integration.rs`. They load
real BPF programs, so they need root + opt-in:

```sh
sudo -E NOCRUFT_E2E=1 cargo test --release
```

Without `NOCRUFT_E2E=1` they silently no-op; `cargo test` in CI without
caps is harmless.

## Project layout

```
crates/nocruft/         userspace Rust binary (cli, tracer, output)
crates/nocruft-bpf/     BPF C source (nocruft.bpf.c) and minimal vmlinux.h
flake.nix               dev shell (clang-unwrapped, libbpf, rustc)
```

`vmlinux.h` is a hand-written minimal header (~40 lines) declaring only the
kernel tracepoint context structs the BPF program reads. CO-RE relocations
resolve actual field offsets against the running kernel's BTF at load time,
so it's portable across kernel versions. If the BPF program ever needs a
new kernel struct, dump it locally with
`bpftool btf dump file /sys/kernel/btf/vmlinux format c` and copy the
relevant subset into `vmlinux.h`.

Regenerate on demand for newer kernel structs.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
