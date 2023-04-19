#ifndef __PERFEVENT_H
#define __PERFEVENT_H
#define TASK_COMM_LEN 16
struct event
{
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    u8 comm[TASK_COMM_LEN];
};

struct event _event = {};
#endif