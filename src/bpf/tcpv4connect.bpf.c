#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpv4connect.h"

const volatile int filter_ports[MAX_PORTS];
const volatile int filter_ports_len = 0;
const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;

#define AF_INET 2

// 保存tid到sock的映射
// 需要注意的是map中保存的是 sock 指针的指针
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct sock *);
} sockets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool filter_port(__u16 port)
{
    int i;
    if (filter_ports_len == 0)
    {
        return false;
    }

    for (i = 0; i < filter_ports_len && i < MAX_PORTS; i++)
    {
        if (port == filter_ports[i])
        {
            return false;
        }
    }
    return true;
}

// 构造event并写入到event map中
static __always_inline void
trace_v4(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 sport, __u16 dport)
{
    struct event event = {};

    event.af = AF_INET;
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid();
    event.ts_us = bpf_ktime_get_ns() / 1000;
    BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
    event.sport = sport;
    event.dport = dport;
    bpf_get_current_comm(event.task, sizeof(event.task));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

// tcp_connect 函数调用时触发
static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = pid_tgid;
    __u32 uid;

    // 如果设置了pid, 则只追踪目标进程的tcp连接
    if (filter_pid && tgid != filter_pid)
    {
        return 0;
    }

    // 如果设置了uid, 则只追目标用户的tcp连接
    uid = bpf_get_current_uid_gid();
    if (filter_uid && uid != filter_uid)
    {
        return 0;
    }

    // 此时 sock 中并没有如何数据, 因此保存指针以便后续使用
    bpf_map_update_elem(&sockets, &pid, &sk, BPF_ANY);
    return 0;
}

// tpc_connect 函数调用结束时触发
static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid;
    struct sock **skpp;
    struct sock *sk;
    __u16 sport = 0;
    __u16 dport;

    skpp = bpf_map_lookup_elem(&sockets, &pid);
    // 如果没有 tid 对应的 sock, 说明此 tid 并未被追踪
    if (!skpp)
    {
        return 0;
    }

    // 返回值不为0时, 意味着tcp连接没有正常建立
    if (ret)
    {
        goto end;
    }

    // 从 sk 读取 sport 与 dport
    sk = *skpp;

    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    // 如果dport不在filter ports中，则停止追踪
    if (filter_port(dport))
    {
        goto end;
    }

    // 写入 event
    trace_v4(ctx, pid, sk, sport, dport);

end:
    bpf_map_delete_elem(&sockets, &pid);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
    return exit_tcp_connect(ctx, ret, 4);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
