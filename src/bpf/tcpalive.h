#ifndef __TCPALIVE_H
#define __TCPALIVE_H

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
    __u32 tgid;
    int newstate;
    __u8 task[TASK_COMM_LEN];
};

struct event _event = {};

#endif