#include "vmlinux.h"
#include "ringbuffer.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF 环形缓冲区（ring buffer
// linux kernel >=  5.8
// 解决了 BPF perf buffer 的内存效率和事件重排问题，同时达到或超过了它的性能
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

// tp/sched/sched_process_exit 是一个 Security Enhanced Linux（SELinux）的挂载点
// 用于控制与进程退出相关的操作, 能够限制进程在退出时的行为，以确保其不会访问或修改其不具备权限的资源
// 1. 对已经终止的进程进行操作的能力
// 2. 对其他进程的信号处理进行干扰的能力
// 3. 能否向其他进程发送信号
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task;
    struct event *ep;
    __u32 tgid, pid;
    __u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    pid = pid_tgid;

    // 忽略线程
    if (pid != tgid)
        return 0;

    ep = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (!ep)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();
    ep->pid = pid;
    ep->ppid = BPF_CORE_READ(task, real_parent, tgid);
    ep->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&(ep->comm), sizeof(ep->comm));

    // 发送 event
    bpf_ringbuf_submit(ep, 0);
    return 0;
}
