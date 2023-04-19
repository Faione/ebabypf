#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile int pid_target = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 跟踪点（tracepoints）是内核静态插桩技术
// 跟踪点在技术上只是放置在内核源代码中的跟踪函数
// 实际上就是在源码中插入的一些带有控制条件的探测点，这些探测点允许事后再添加处理函数
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid_target && pid_target != pid)
        return false;
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}