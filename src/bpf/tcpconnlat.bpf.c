#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpconnlat.h"

#define MAX_ENTRIES 4096

const volatile __u32 target_tgid = 0;
const volatile __u64 target_min_us = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, struct pid_data);
} starts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int
trace_connect(struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = pid_tgid;

    struct pid_data pdata = {};

    if (target_tgid && target_tgid != tgid)
        return 0;

    bpf_get_current_comm(&pdata.comm, sizeof(pdata.comm));
    pdata.time_start = bpf_ktime_get_ns();
    pdata.tgid = tgid;
    bpf_map_update_elem(&starts, &sk, &pdata, BPF_ANY);
    return 0;
}

static __always_inline int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
    struct pid_data *pdatap;
    struct event event = {};
    __s64 delta;
    __u64 current_time;

    if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
        return 0;
    pdatap = bpf_map_lookup_elem(&starts, &sk);
    if (!pdatap)
        return 0;

    current_time = bpf_ktime_get_ns();
    delta = (__s64)(current_time - pdatap->time_start);
    if (delta < 0)
        goto cleanup;

    event.delta = delta / 1000U;
    if (target_min_us && event.delta < target_min_us)
        goto cleanup;

    __builtin_memcpy(&event.comm, pdatap->comm, sizeof(event.comm));
    event.time_comp = current_time / 1000U;
    event.tgid = pdatap->tgid;
    event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event.af = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (event.af == AF_INET)
    {
        event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }
    else
    {
        BPF_CORE_READ_INTO(&event.saddr_v6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&event.daddr_v6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
    bpf_map_delete_elem(&starts, &sk);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_conenct, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
    return handle_tcp_rcv_state_process(ctx, sk);
}