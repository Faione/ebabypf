#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event
{
    __u32 pid;
    __u32 tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct event);
} sigevents SEC(".maps");

// target_pid 为接收信号的进程
static __always_inline int probe_entry(__u64 target_pid, int sig)
{
    struct event event = {};
    // 发送信号的进程
    __u64 pid_tgid;
    __u32 tid;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = pid_tgid;

    event.pid = pid_tgid >> 32;
    event.tpid = target_pid;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(&sigevents, &tid, &event, BPF_ANY);
    return 0;
}

static __always_inline int probe_exit(void *ctx, int ret)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct event *eventp;

    eventp = bpf_map_lookup_elem(&sigevents, &tid);
    if (!eventp)
        return 0;

    eventp->ret = ret;
    bpf_printk("PID %d (%s) sent signal %d to PID %d, ret = %d",
               eventp->pid, eventp->comm, eventp->sig, eventp->tpid, ret);

    bpf_map_delete_elem(&sigevents, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    pid_t target_pid = ctx->args[0];
    int sig = ctx->args[1];

    return probe_entry(target_pid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
    return probe_exit(ctx, ctx->ret);
}