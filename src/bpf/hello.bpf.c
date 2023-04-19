#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 不同的证书会影响到一些函数的使用
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC 是 bpf_helpers.h 中定义的一个宏，用来指明ebpf程序挂载的位置
// "kprobe/sys_clone" 意味着此 ebpf 程序挂载到 sys_clone 的 kprobe 挂载点(最新版本的内核中提供了SYSCALL宏，用来为syscall增加架构前缀，此处手动增加即可)
// BPF_KPROBE 是 bpf_tracing.h 中定义的一个宏, 用于声明内核探针的宏
SEC("kprobe/__x64_sys_clone")
int BPF_KPROBE(sys_clone)
{
    char saying[] = "Hello, World!\n";

    bpf_trace_printk(saying, sizeof(saying));
    return 0;
}