// SPDX-License-Identifier: GPL-2.0
// Tracepoint program for sys_enter_connect — captures outbound connection events.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET  2
#define AF_INET6 10

struct connect_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 dst_port;   // network byte order
    __u8  dst_ip[16]; // IPv4 in first 4 bytes, IPv6 in all 16
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} connect_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event ev = {};

    ev.timestamp_ns = bpf_ktime_get_ns();

    __u64 id = bpf_get_current_pid_tgid();
    ev.pid = (__u32)(id >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    ev.uid = (__u32)uid_gid;

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    // Read the sockaddr to extract family and destination.
    struct sockaddr sa = {};
    void *uaddr = (void *)ctx->args[1];
    bpf_probe_read_user(&sa, sizeof(sa), uaddr);
    ev.family = sa.sa_family;

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        ev.dst_port = sin.sin_port;
        bpf_probe_read_kernel(&ev.dst_ip, 4, &sin.sin_addr);
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), uaddr);
        ev.dst_port = sin6.sin6_port;
        bpf_probe_read_kernel(&ev.dst_ip, 16, &sin6.sin6_addr);
    }

    bpf_perf_event_output(ctx, &connect_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
