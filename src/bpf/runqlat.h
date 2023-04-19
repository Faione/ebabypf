#ifndef __RUNQLAT_H
#define __RUNQLAT_H

#define MAX_ENTRIES 10240
#define TASK_RUNNING 0

#define TASK_COMM_LEN 16
#define MAX_BUCKETS 26

// 直方图event
// bucket:[0, 2), [2, 4), [4, 8), [8, 16) ... [2^25, inf)
struct hist
{
    __u32 bucket[MAX_BUCKETS];
    __u8 comm[TASK_COMM_LEN];
};

struct hist _hist = {};

#endif