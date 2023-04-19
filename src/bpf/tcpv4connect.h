#ifndef __TCPCONNECT_H
#define __TCPCONNECT_H
/* The maximum number of ports to filter */
#define MAX_PORTS 64

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

struct ipv4_flow_key
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct event
{
    __u32 saddr_v4;
    __u32 daddr_v4;
    u8 task[TASK_COMM_LEN];
    __u64 ts_us;
    __u32 af;
    __u32 pid;
    __u32 uid;
    __u16 sport;
    __u16 dport;
};

// 在bss段中占位，从而能够在skel中访问
struct event _event = {};

#endif /* __TCPCONNECT_H */