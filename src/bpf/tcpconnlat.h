#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

struct pid_data
{
    __u8 comm[TASK_COMM_LEN];
    __u64 time_start;
    __u64 tgid;
};

struct event
{
    union
    {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union
    {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    __u8 comm[TASK_COMM_LEN];
    __u64 delta;
    __u64 time_comp;
    __u32 tgid;
    int af;
    __u16 lport;
    __u16 dport;
};

struct event _event = {};
#endif