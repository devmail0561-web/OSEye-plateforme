// SPDX-License-Identifier: GPL-2.0
// Tracepoint program for sys_enter_openat — captures file open events.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct openat_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __s32 flags;
    char  comm[16];
    char  filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} openat_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct openat_event ev = {};

    ev.timestamp_ns = bpf_ktime_get_ns();

    __u64 id = bpf_get_current_pid_tgid();
    ev.pid = (__u32)(id >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    ev.uid = (__u32)uid_gid;

    ev.flags = (__s32)ctx->args[2];

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), filename);

    bpf_perf_event_output(ctx, &openat_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
