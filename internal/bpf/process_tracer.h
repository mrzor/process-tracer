#ifndef __PROCESS_TRACER_H
#define __PROCESS_TRACER_H

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_EXEC = 1,
    EVENT_EXIT = 2,
    EVENT_TCP_CONNECT = 3,
    EVENT_TCP_CLOSE = 4,
    EVENT_EXEC_ENV_CHUNK = 5,
    EVENT_ENV_VAR = 6,
    EVENT_EXEC_CANDIDATE = 7,
    EVENT_FORK = 8,
    EVENT_ANCESTOR_TRACE = 9,
};

// Full ancestor-chain dump emitted BEFORE EVENT_EXEC_CANDIDATE /
// weld-fail when BPF's 8-level tracking walk couldn't find any tracked
// ancestor. Userland correlates by (pid, timestamp_ns) with the
// exec_unclaimed / weld_fail event that follows. Purpose: answer
// "what *is* the ancestor chain, and does it reach a tracked PID at
// all, and if so how far up?" — a separate 16-level walk records
// tgid/comm/ns_inum/tracked for each hop, without stopping at the
// first tracked pid.
#define ANCESTOR_TRACE_MAX_HOPS 16

struct ancestor_hop {
    __u32 tgid;
    __u32 pid_ns_inum;
    char comm[TASK_COMM_LEN];
    __u8 tracked;          // 1 if this tgid is in tracked_pids at sample time
    __u8 _pad[3];
};

struct ancestor_trace_event {
    __u32 pid;             // subject: the exec'ing (or forking-child) pid
    __u32 ppid;            // immediate parent tgid, for quick correlation
    __u32 uid;
    __u32 _pad1;           // align to 8 before timestamp
    __u64 timestamp;
    __u8 type;             // EVENT_ANCESTOR_TRACE
    __u8 num_hops;         // 0..ANCESTOR_TRACE_MAX_HOPS
    __u8 reason;           // 0=exec_no_ancestor, 1=fork_no_ancestor
    __u8 _pad2[5];
    struct ancestor_hop hops[ANCESTOR_TRACE_MAX_HOPS];
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
            __u32 is_container_init;   // 1 if PID 1 in a non-root PID namespace
            __u32 ns_level;            // PID namespace nesting level (0 = root)
            __u32 tracked_ancestor;    // PID of the ancestor found in tracked_pids
                                       // via ancestor walk (0 if immediate parent was tracked)
            __u32 pid_ns_inum;         // inode number of task->nsproxy->pid_ns_for_children->ns;
                                       // lets userland group events by PID namespace, catching
                                       // container-runtime ns transitions that would otherwise be
                                       // invisible in flat host-PID view
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

// Environment chunk event - variable size, sent separately
// Contains both argv and environ data
#define MAX_ENV_CHUNK_SIZE 15000

struct env_chunk_event {
    __u32 pid;
    __u32 ppid;        // Not used, but keeps layout consistent
    __u32 uid;         // Not used, but keeps layout consistent
    __u32 _pad1;       // Padding before timestamp (matches Event struct)
    __u64 timestamp;   // Not used, but keeps layout consistent
    __u8 type;         // EVENT_EXEC_ENV_CHUNK
    __u8 _pad2[7];     // Padding (matches Event struct)
    __u32 chunk_id;
    __u32 data_size;
    __u32 argc;        // Number of argv strings at start of data
    __u8 is_final;
    __u8 truncated;
    __u8 _pad3[2];     // Align to 4 bytes
    char data[MAX_ENV_CHUNK_SIZE];
};

// Individual environment variable event - for streaming large envp arrays
#define MAX_ENV_VAR_SIZE 512

struct env_var_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 _pad1;       // Padding before timestamp
    __u64 timestamp;
    __u8 type;         // EVENT_ENV_VAR
    __u8 _pad2[7];     // Padding (matches Event struct)
    __u16 var_index;   // Position in argv/envp array (0-2047)
    __u16 total_vars;  // Total count (0 = unknown yet)
    __u8 is_argv;      // 0=env, 1=argv
    __u8 is_final;     // 1 if this is last variable
    __u8 truncated;    // 1 if variable was truncated
    __u8 _pad3;        // Padding
    __u16 data_size;   // Actual data length
    __u16 _pad4;       // Padding to align to 8 bytes
    char data[MAX_ENV_VAR_SIZE];
};

// State tracking for tail call continuation
struct env_stream_state {
    __u64 argv_ptr;     // Pointer to argv array
    __u64 envp_ptr;     // Pointer to envp array
    __u16 var_index;    // Current index being processed
    __u16 argc;         // Total arg count (captured early)
    __u8 processing_env; // 0=argv, 1=envp
    __u8 _pad[3];       // Padding
    __u64 timestamp;    // Event timestamp
    __u32 ppid;         // Parent PID
    __u32 uid;          // User ID
};

#endif /* __PROCESS_TRACER_H */
