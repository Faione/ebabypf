#include "vmlinux.h"
#include "perfevent.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid;
    __u32 pid, tgid, uid;
    struct task_struct *task;
    struct event event = {};

    pid_tgid = bpf_get_current_pid_tgid();
    uid = bpf_get_current_uid_gid();

    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    event.pid = tgid;
    event.uid = uid;
    task = (struct task_struct *)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}