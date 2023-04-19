#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// fentry/fexit 要求内核 >= 5.5
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 相比于 kprobe, 使用 fentry 可以直接访问函数的指针参数，而不需要帮助程序
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

// 相比于 kretprobe, fexit可以同时访问函数的输入参数和返回值
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exxit, int dfd, struct filename *name, long ret)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}