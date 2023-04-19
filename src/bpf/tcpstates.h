#ifndef __TCPSTATES_H
#define __TCPSTATES_H

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

#define AF_INET 2
#define AF_INTT6 10

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
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u64 skaddr;
    __u64 time_us;
    __u64 delta_us;
    __u32 tgid;
    int oldstate;
    int newstate;
    __u8 task[TASK_COMM_LEN];
};

struct event _event = {};

#endif