#ifndef __RINGBUFFER_H
#define __RINGBUFFER_H

#define TASK_COMM_LEN 16
#define MAX_FILENAM_LEN 127

struct event
{
    __u32 pid;
    __u32 ppid;
    __u32 exit_code;
    __u8 comm[TASK_COMM_LEN];
};

struct event _event = {};

#endif