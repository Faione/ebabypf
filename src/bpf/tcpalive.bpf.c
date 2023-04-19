#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tcpalive.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, struct event);
} conns SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    __u16 family = ctx->family;
    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;
    struct event event = {};

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (ctx->newstate == TCP_CLOSE)
    {
        bpf_map_delete_elem(&conns, &sk);
        return 0;
    }

    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.family = family;
    event.sport = sport;
    event.dport = dport;
    event.newstate = ctx->newstate;
    bpf_get_current_comm(&event.task, sizeof(event.task));

    if (family == AF_INET)
    {
        bpf_probe_read_kernel(&event.saddr_v4, sizeof(&event.saddr_v4), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event.daddr_v4, sizeof(&event.daddr_v4), &sk->__sk_common.skc_daddr);
    }
    else
    {
        bpf_probe_read_kernel(&event.saddr_v6, sizeof(&event.saddr_v6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event.daddr_v6, sizeof(&event.daddr_v6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    if (ctx->newstate == TCP_CLOSE)
    {
        bpf_map_delete_elem(&conns, &sk);
    }
    else
    {
        bpf_map_update_elem(&conns, &sk, &event, BPF_ANY);
    }

    return 0;
}
