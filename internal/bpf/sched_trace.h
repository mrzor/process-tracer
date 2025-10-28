#ifndef __SCHED_TRACE_H
#define __SCHED_TRACE_H

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_EXEC = 1,
    EVENT_EXIT = 2,
};

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 exit_code;
    __u8 type;
    char comm[TASK_COMM_LEN];
};

#endif /* __SCHED_TRACE_H */
