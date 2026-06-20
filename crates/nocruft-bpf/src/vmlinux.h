/*
 * Minimal vmlinux.h for nocruft.
 *
 * This is NOT the full bpftool BTF dump. It declares only:
 *   - integer typedefs
 *   - networking typedefs (referenced by libbpf's bpf_helper_defs.h for
 *     helpers we don't call, but the declarations must still type-check)
 *   - forward declarations of opaque kernel structs touched by helper
 *     prototypes we don't call
 *   - BPF map-type and update-flag enums we DO use
 *   - the tracepoint context structs nocruft's BPF program reads, with
 *     `preserve_access_index` so CO-RE relocates field offsets at load
 *     time against the running kernel's BTF.
 *
 * If a future BPF feature in this repo needs a new kernel struct, dump it
 * locally with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`
 * and copy the relevant subset here.
 */

#ifndef __NOCRUFT_VMLINUX_H__
#define __NOCRUFT_VMLINUX_H__

/* ----- primitive typedefs ----- */

typedef signed char        __s8;
typedef unsigned char      __u8;
typedef signed short       __s16;
typedef unsigned short     __u16;
typedef signed int         __s32;
typedef unsigned int       __u32;
typedef signed long long   __s64;
typedef unsigned long long __u64;
typedef _Bool              bool;

/* Network byte-order aliases. We do not generate or consume network bytes,
 * but bpf_helper_defs.h declares helpers that take these types, so the
 * names must exist. Alias them to the matching unsigned-width type. */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u32 __wsum;
typedef __u32 __sum16;

/* ----- forward declarations of opaque kernel structs -----
 * Helpers we never call still appear in bpf_helper_defs.h's signatures,
 * so the type names must be known. Empty/forward declarations are enough
 * because we never instantiate or read these. */
struct __sk_buff;
struct bpf_sock;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct bpf_sock_tuple;
struct bpf_tcp_sock;
struct bpf_xfrm_state;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_pidns_info;
struct bpf_sysctl;
struct bpf_tunnel_key;
struct bpf_redir_neigh;
struct bpf_dynptr;
struct bpf_timer;
struct bpf_spin_lock;
struct bpf_func_state;
struct btf_ptr;
struct xdp_md;
struct xdp_buff;
struct iphdr;
struct ipv6hdr;
struct tcphdr;
struct udphdr;
struct pt_regs;
struct path;
struct task_struct;
struct cgroup;
struct sock;
struct sk_msg_md;
struct sk_reuseport_md;
struct seq_file;
struct linux_binprm;
struct inode;
struct file;
struct dentry;
struct super_block;
struct mptcp_sock;
struct unix_sock;

/* ----- BPF enums actually used ----- */

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
    BPF_F_LOCK = 4,
};

/* ----- tracepoint context structs ----- */

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

/* tracepoint: sched/sched_process_fork */
struct trace_event_raw_sched_process_fork {
    unsigned long long __nocruft_pad_header;
    char parent_comm[16];
    int  parent_pid;
    char child_comm[16];
    int  child_pid;
};

/* tracepoint: sched/sched_process_exit (and other "_template" events) */
struct trace_event_raw_sched_process_template {
    unsigned long long __nocruft_pad_header;
    char comm[16];
    int  pid;
    int  prio;
};

/* tracepoint: syscalls/sys_enter_* */
struct trace_event_raw_sys_enter {
    unsigned long long __nocruft_pad_header;
    long id;
    unsigned long args[6];
};

/* tracepoint: syscalls/sys_exit_* */
struct trace_event_raw_sys_exit {
    unsigned long long __nocruft_pad_header;
    long id;
    long ret;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __NOCRUFT_VMLINUX_H__ */
