#ifndef __SCHED_TRACE_H
#define __SCHED_TRACE_H

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_EXEC = 1,
    EVENT_EXIT = 2,
    EVENT_TCP_CONNECT = 3,
    EVENT_TCP_CLOSE = 4,
};

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp;
    __u8 type;
    __u8 _pad[7];  // Explicit padding for alignment

    union {
        // Process event fields
        struct {
            __u32 exit_code;
            char comm[TASK_COMM_LEN];
        } proc;

        // TCP event fields
        struct {
            __u64 skaddr;      // Socket address (used as span ID)
            __u8 saddr[16];    // Source IP (v4 or v6)
            __u8 daddr[16];    // Destination IP (v4 or v6)
            __u16 sport;       // Source port
            __u16 dport;       // Destination port
            __u16 family;      // AF_INET or AF_INET6
            __u16 _pad2;       // Padding to align to 8 bytes
        } tcp;
    } data;
};

// TCP span tracking info stored in BPF map
struct tcp_span_info {
    __u64 start_time;
    __u32 pid;
    __u16 family;
};

#endif /* __SCHED_TRACE_H */
