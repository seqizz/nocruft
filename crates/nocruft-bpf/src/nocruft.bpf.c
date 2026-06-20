// nocruft eBPF program.
//
// Checkpoint 5: process-tree tracking + openat(O_CREAT) + mkdirat + renameat2
// destination capture.
//
// All three creation syscalls share the same enter/exit pattern:
//   enter: if current task is tracked, stash (dirfd, path[, flags]) keyed
//          by pid_tgid in enter_ctx.
//   exit:  on success (ret >= 0 for openat, ret == 0 for mkdirat/renameat2),
//          emit an event to the ringbuf carrying the stashed data. Always
//          delete the enter_ctx entry on exit, success or not.
//
// renameat2 reports the destination (newdfd, newname); we do not yet emit a
// "source moved away" event. RENAME_EXCHANGE swaps both paths and neither is
// strictly "created"; we still report newname which is acceptable noise for
// MVP and documented as a limitation.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define O_CREAT     0x40
#define O_DIRECTORY 0x10000
#define PATH_BUF_SZ 256

#define EV_FORK_TRACKED  1
#define EV_EXIT_TRACKED  2
#define EV_OPENAT_CREATE 3
#define EV_MKDIRAT       4
#define EV_RENAMEAT2     5
#define EV_SYMLINKAT     6
#define EV_LINKAT        7
#define EV_CHDIR         8
#define EV_FCHDIR        9
// Internal: a successful open of a directory (without O_CREAT). Tracked so
// userspace can resolve subsequent fchdir(fd) events to the directory path.
// Does NOT appear as a creation in user output.
#define EV_OPENAT_DIR    10
#define EV_MKNODAT       11

// open(O_CREAT) and creat() both equivalent to "create a file"; reuse code
// for openat's exit shape. creat() is equivalent to open(O_CREAT|O_WRONLY|O_TRUNC).
#define CREAT_FLAGS (0x40 | 0x01 | 0x200)

struct event {
    __u32 etype;
    __u32 pid;
    __u32 ppid;
    __s32 dirfd;
    __u32 flags;
    __u32 truncated;
    __s32 result_fd;   // for EV_OPENAT_DIR: the fd returned; otherwise -1
    __u32 _pad;
    __u64 ts_ns;
    char  path[PATH_BUF_SZ];
};

struct enter_args {
    __s32 dirfd;
    __u32 flags;
    __u32 truncated;
    __u32 _pad;
    char  path[PATH_BUF_SZ];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

// enter_ctx scratch map: holds one entry per in-flight syscall keyed by
// pid_tgid. A normal task has at most one in-flight syscall, so this needs
// to be sized to the number of *concurrently-tracked tasks* doing tracked
// syscalls, not the rate of syscalls. 4096 is comfortable for any
// nix-shell session; if it ever fills (LRU semantics keep things working
// in degraded mode), we'd see lost path events.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct enter_args);
} enter_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ----- fork / exit -----

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_pid = (__u32)bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&tracked_pids, &parent_pid))
        return 0;

    __u32 child_pid = (__u32)BPF_CORE_READ(ctx, child_pid);
    __u8 one = 1;
    bpf_map_update_elem(&tracked_pids, &child_pid, &one, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->etype = EV_FORK_TRACKED;
        e->pid = child_pid;
        e->ppid = parent_pid;
        e->ts_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (bpf_map_delete_elem(&tracked_pids, &pid) != 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->etype = EV_EXIT_TRACKED;
        e->pid = pid;
        e->ts_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ----- enter/exit helper: stash and emit, used by per-syscall handlers -----

// Inline-able helper: copy user path into ea.path with truncation tracking,
// then publish to enter_ctx. Returns 0 on success, nonzero on failure.
static __always_inline int
stash_enter(__s32 dirfd, __u32 flags, const char *upath)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)id;
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return -1;

    struct enter_args ea = {};
    ea.dirfd = dirfd;
    ea.flags = flags;

    long n = bpf_probe_read_user_str(ea.path, sizeof(ea.path), upath);
    if (n < 0)
        return -1;
    if (n == sizeof(ea.path))
        ea.truncated = 1;

    bpf_map_update_elem(&enter_ctx, &id, &ea, BPF_ANY);
    return 0;
}

// Variant of stash_enter for syscalls that take a dirfd but no path
// (e.g. fchdir). Caller fills dirfd; the path field is left empty.
static __always_inline int
stash_enter_nopath(__s32 dirfd, __u32 flags)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)id;
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return -1;

    struct enter_args ea = {};
    ea.dirfd = dirfd;
    ea.flags = flags;
    // ea.path is already zeroed by the initializer.

    bpf_map_update_elem(&enter_ctx, &id, &ea, BPF_ANY);
    return 0;
}

// Inline-able helper: read the stashed enter_ctx, emit an event of `etype` on
// success (ret_ok != 0), and always delete the enter_ctx entry. `result_fd`
// is included as-is in the event (used by EV_OPENAT_DIR); pass -1 when not
// applicable.
static __always_inline void
emit_exit(__u32 etype, long ret_ok, __s32 result_fd)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct enter_args *ea = bpf_map_lookup_elem(&enter_ctx, &id);
    if (!ea)
        return;

    if (!ret_ok)
        goto done;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto done;
    __builtin_memset(e, 0, sizeof(*e));
    e->etype = etype;
    e->pid = (__u32)id;
    e->dirfd = ea->dirfd;
    e->flags = ea->flags;
    e->truncated = ea->truncated;
    e->result_fd = result_fd;
    e->ts_ns = bpf_ktime_get_ns();
    __builtin_memcpy(e->path, ea->path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);

done:
    bpf_map_delete_elem(&enter_ctx, &id);
}

// ----- openat -----

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 flags = (__u32)ctx->args[2];
    // Two reasons to capture: O_CREAT (it's a creation), or O_DIRECTORY
    // (so userspace can resolve a later fchdir(fd) to a path). Everything
    // else (library loads etc.) we skip to keep ringbuf traffic low.
    if (!(flags & (O_CREAT | O_DIRECTORY)))
        return 0;
    stash_enter((__s32)ctx->args[0], flags, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct enter_args *ea = bpf_map_lookup_elem(&enter_ctx, &id);
    if (!ea)
        return 0;

    // Branch by what the enter filter let through. O_CREAT wins if both set.
    __u32 etype;
    if (ea->flags & O_CREAT)
        etype = EV_OPENAT_CREATE;
    else
        etype = EV_OPENAT_DIR;

    long ok = ctx->ret >= 0;
    // For EV_OPENAT_DIR carry the resulting fd so userspace can map fd->path
    // and resolve fchdir later. For EV_OPENAT_CREATE the fd is irrelevant.
    __s32 result_fd = (etype == EV_OPENAT_DIR && ok) ? (__s32)ctx->ret : -1;
    emit_exit(etype, ok, result_fd);
    return 0;
}

// ----- mkdir (legacy; coreutils mkdir still calls this on x86_64 glibc) -----

#define AT_FDCWD_VAL (-100)

SEC("tracepoint/syscalls/sys_enter_mkdir")
int handle_mkdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter(AT_FDCWD_VAL, 0, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int handle_mkdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ok = ctx->ret == 0;
    emit_exit(EV_MKDIRAT, ok, -1);
    return 0;
}

// ----- mkdirat -----

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_mkdirat_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter((__s32)ctx->args[0], 0, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int handle_mkdirat_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ok = ctx->ret == 0;
    emit_exit(EV_MKDIRAT, ok, -1);
    return 0;
}

// ----- renameat2 (destination only for MVP) -----

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
    // args[2] = newdfd, args[3] = newname, args[4] = flags
    __u32 flags = (__u32)ctx->args[4];
    stash_enter((__s32)ctx->args[2], flags, (const char *)ctx->args[3]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int handle_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ok = ctx->ret == 0;
    emit_exit(EV_RENAMEAT2, ok, -1);
    return 0;
}

// ----- legacy rename (no dfd) -----

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename_enter(struct trace_event_raw_sys_enter *ctx)
{
    // args[0]=oldname, args[1]=newname. Emit destination.
    stash_enter(AT_FDCWD_VAL, 0, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int handle_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_RENAMEAT2, ctx->ret == 0, -1);
    return 0;
}

// ----- renameat (no flags, has dfds) -----

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat_enter(struct trace_event_raw_sys_enter *ctx)
{
    // args[0]=olddfd, [1]=oldname, [2]=newdfd, [3]=newname.
    stash_enter((__s32)ctx->args[2], 0, (const char *)ctx->args[3]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int handle_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_RENAMEAT2, ctx->ret == 0, -1);
    return 0;
}

// ----- open (legacy: open(pathname, flags, mode)) -----

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 flags = (__u32)ctx->args[1];
    if (!(flags & O_CREAT))
        return 0;
    stash_enter(AT_FDCWD_VAL, flags, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_OPENAT_CREATE, ctx->ret >= 0, -1);
    return 0;
}

// ----- creat -----

SEC("tracepoint/syscalls/sys_enter_creat")
int handle_creat_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter(AT_FDCWD_VAL, CREAT_FLAGS, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int handle_creat_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_OPENAT_CREATE, ctx->ret >= 0, -1);
    return 0;
}

// ----- symlink(target, linkpath) -----

SEC("tracepoint/syscalls/sys_enter_symlink")
int handle_symlink_enter(struct trace_event_raw_sys_enter *ctx)
{
    // args[0]=target (we ignore it; we report where the new symlink is
    // placed), args[1]=linkpath.
    stash_enter(AT_FDCWD_VAL, 0, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int handle_symlink_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_SYMLINKAT, ctx->ret == 0, -1);
    return 0;
}

// ----- symlinkat(target, newdfd, linkpath) -----

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int handle_symlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter((__s32)ctx->args[1], 0, (const char *)ctx->args[2]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlinkat")
int handle_symlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_SYMLINKAT, ctx->ret == 0, -1);
    return 0;
}

// ----- link(oldpath, newpath) -----

SEC("tracepoint/syscalls/sys_enter_link")
int handle_link_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter(AT_FDCWD_VAL, 0, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int handle_link_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_LINKAT, ctx->ret == 0, -1);
    return 0;
}

// ----- linkat(olddfd, oldpath, newdfd, newpath, flags) -----

SEC("tracepoint/syscalls/sys_enter_linkat")
int handle_linkat_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter((__s32)ctx->args[2], 0, (const char *)ctx->args[3]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_linkat")
int handle_linkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_LINKAT, ctx->ret == 0, -1);
    return 0;
}

// ----- chdir / fchdir (for userspace cwd tracking) -----
//
// We emit these as ordinary events. Userspace reads them in order and
// maintains a per-pid cwd map, so any creation event's base is the cwd that
// was current at the moment the syscall fired. This eliminates the
// /proc-readlink race for processes that chdir between calls.

SEC("tracepoint/syscalls/sys_enter_chdir")
int handle_chdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter(AT_FDCWD_VAL, 0, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int handle_chdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_CHDIR, ctx->ret == 0, -1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int handle_fchdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter_nopath((__s32)ctx->args[0], 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int handle_fchdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_FCHDIR, ctx->ret == 0, -1);
    return 0;
}

// ----- openat2 -----
//
// args[0]=dirfd, args[1]=filename, args[2]=struct open_how *, args[3]=size.
// We read the first u64 of open_how to get flags (it's the first field).

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2_enter(struct trace_event_raw_sys_enter *ctx)
{
    const void *how_ptr = (const void *)ctx->args[2];
    __u64 size = ctx->args[3];
    if (size < sizeof(__u64))
        return 0;

    __u64 flags64 = 0;
    if (bpf_probe_read_user(&flags64, sizeof(flags64), how_ptr) != 0)
        return 0;

    __u32 flags = (__u32)flags64;
    if (!(flags & (O_CREAT | O_DIRECTORY)))
        return 0;

    stash_enter((__s32)ctx->args[0], flags, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int handle_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct enter_args *ea = bpf_map_lookup_elem(&enter_ctx, &id);
    if (!ea)
        return 0;

    __u32 etype = (ea->flags & O_CREAT) ? EV_OPENAT_CREATE : EV_OPENAT_DIR;
    long ok = ctx->ret >= 0;
    __s32 result_fd = (etype == EV_OPENAT_DIR && ok) ? (__s32)ctx->ret : -1;
    emit_exit(etype, ok, result_fd);
    return 0;
}

// ----- mknod / mknodat -----
//
// mknod(path, mode, dev): args[0]=path.
// mknodat(dirfd, path, mode, dev): args[0]=dirfd, args[1]=path.

SEC("tracepoint/syscalls/sys_enter_mknod")
int handle_mknod_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter(AT_FDCWD_VAL, 0, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknod")
int handle_mknod_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_MKNODAT, ctx->ret == 0, -1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int handle_mknodat_enter(struct trace_event_raw_sys_enter *ctx)
{
    stash_enter((__s32)ctx->args[0], 0, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknodat")
int handle_mknodat_exit(struct trace_event_raw_sys_exit *ctx)
{
    emit_exit(EV_MKNODAT, ctx->ret == 0, -1);
    return 0;
}
