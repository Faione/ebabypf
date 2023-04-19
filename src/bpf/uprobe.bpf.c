#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// uprobe是一种用户空间探针，uprobe探针允许在用户空间程序中动态插桩
// 插桩位置包括：函数入口、特定偏移处，以及函数返回处
// 当我们定义uprobe时，内核会在附加的指令上创建快速断点指令（x86机器上为int3指令
// 当程序执行到该指令时，内核将触发事件，程序陷入到内核态，并以回调函数的方式调用探针函数，执行完探针函数再返回到用户态继续执行后序的指令
//
// uprobe基于文件
// 当一个二进制文件中的一个函数被跟踪时，所有使用到这个文件的进程都会被插桩，包括那些尚未启动的进程，这样就可以在全系统范围内跟踪系统调用
SEC("uretprobe//bin/zsh:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    __u32 pid;

    if (!ret)
    {
        return 0;
    }

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;
    // readline 返回值是 char *
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("PID %d (%s) read: %s", pid, comm, str);

    return 0;
}