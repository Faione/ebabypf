#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno.h>
#include "runqlat.h"
#include "bits.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// runqlat 用于测量一个任务在被调度到 CPU 上运行之前在运行队列中等待的时间

// 以tgid进行划分
const volatile bool per_process = false;
// 以pid进行划分
const volatile bool per_thread = false;
// 以namespace进行划分
const volatile bool per_pidns = false;

const volatile bool ms = false;

const volatile __u64 target_tgid = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} enqueue_times SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct hist);
} hists SEC(".maps");

// 记录入队时间
static __always_inline int trace_enqueue(__u32 tgid, __u32 pid)
{
    __u64 ts;
    if (!pid)
        return 0;

    if (target_tgid && target_tgid != tgid)
        return 0;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&enqueue_times, &pid, &ts, BPF_ANY);
    return 0;
}

// 获取 pid namespace
static __always_inline unsigned int pid_namespace(struct task_struct *task)
{
    struct pid *pid;
    unsigned int level;
    struct upid upid;
    unsigned int inum;

    pid = BPF_CORE_READ(task, thread_pid);
    level = BPF_CORE_READ(pid, level);
    bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
    inum = BPF_CORE_READ(upid.ns, ns.inum);

    return inum;
}

static __always_inline int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
    struct hist *histp;
    struct hist def_hist = {};
    __u64 *last_enq_timep, bucket_index;
    __u32 pid, hist_key;
    __s64 delta;

    // prev task 将入队

    if (BPF_CORE_READ(prev, __state) == TASK_RUNNING)
        trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

    pid = BPF_CORE_READ(next, pid);
    last_enq_timep = bpf_map_lookup_elem(&enqueue_times, &pid);
    if (!last_enq_timep)
        return 0;

    // task next即将执行，计算在队时间
    delta = bpf_ktime_get_ns() - *last_enq_timep;
    if (delta < 0)
        goto cleanup;

    // 根据设置确定hist的保存方式
    if (per_process)
        hist_key = BPF_CORE_READ(next, tgid);
    else if (per_thread)
        hist_key = pid;
    else if (per_pidns)
        hist_key = pid_namespace(next);
    else
        hist_key = -1;

    histp = bpf_map_lookup_elem(&hists, &hist_key);
    if (!histp)
    {
        bpf_probe_read_kernel_str(&(def_hist.comm), sizeof(def_hist.comm), next->comm);
        bpf_map_update_elem(&hists, &hist_key, &def_hist, BPF_ANY);
    }

    histp = bpf_map_lookup_elem(&hists, &hist_key);
    if (!histp)
        return 0;

    if (ms)
        delta /= 1000000U;
    else
        delta /= 1000U;

    bucket_index = log2l(delta);
    if (bucket_index >= MAX_BUCKETS)
        bucket_index = MAX_BUCKETS - 1;

    __sync_fetch_and_add(&histp->bucket[bucket_index], 1);

cleanup:
    bpf_map_delete_elem(&enqueue_times, &pid);
    return 0;
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *task)
{
    return trace_enqueue(BPF_CORE_READ(task, tgid), BPF_CORE_READ(task, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *task)
{
    return trace_enqueue(BPF_CORE_READ(task, tgid), BPF_CORE_READ(task, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch,
             bool preempt,
             struct task_struct *prev,
             struct task_struct *next)
{
    return handle_switch(preempt, prev, next);
}