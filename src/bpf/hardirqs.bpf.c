#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hardirqs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool enable_ns = false;

// 在 Linux 内核中，每个中断处理程序都有一个唯一的名称，称为中断向量
// hardirqs 通过检查每个中断处理程序的中断向量，来监控内核中的中断处理程序
// 当内核接收到一个中断时，它会查找与该中断相关的中断处理程序，并执行该程序
// hardirqs 通过检查内核中执行的中断处理程序，来监控内核中的中断处理程序
// 另外，hardirqs 还可以通过注入 BPF 程序到内核中，来捕获内核中的中断处理程序
// 这样，hardirqs 就可以监控内核中执行的中断处理程序，并收集有关它们的信息

#define MAX_ENTRIES 256

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct irq_key);
    __type(value, struct info);
} infos SEC(".maps");

static __always_inline int
handle_entry(int irq, struct irqaction *action)
{
    __u32 time_key = 0;
    __u64 time_start = bpf_ktime_get_ns();

    bpf_map_update_elem(&start, &time_key, &time_start, BPF_ANY);
    return 0;
}

static struct info zero;

static __always_inline int
handle_exit(int irq, struct irqaction *action)
{
    struct irq_key ikey = {};
    struct info *info;

    __u32 time_key = 0;
    __u64 delta;
    __u64 *time_startp;

    time_startp = bpf_map_lookup_elem(&start, &time_key);
    if (!time_startp)
        return 0;

    delta = bpf_ktime_get_ns() - *time_startp;
    if (enable_ns)
        delta /= 1000U;

    bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));

    info = bpf_map_lookup_elem(&infos, &ikey);
    if (!info)
    {
        bpf_map_update_elem(&infos, &ikey, &zero, BPF_ANY);
    }
    info = bpf_map_lookup_elem(&infos, &ikey);
    if (!info)
        return 0;

    info->count++;
    info->sum += delta;

    return 0;
}

// tp_btf/irq_handler_entry 可以进行静态类型数据采样，从而提供更好的调试支持
SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
{
    return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
{
    return handle_exit(irq, action);
}

// raw_tp/irq_handler_entry 只能处理简单的 C 数据类型，如整型、指针等
SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action)
{
    return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action)
{
    return handle_exit(irq, action);
}