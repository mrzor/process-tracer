//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sched_trace.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Map to track PIDs in our process tree */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, u8);
} tracked_pids SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, ppid;
    u64 uid_gid;
    u8 val = 1;

    uid_gid = bpf_get_current_uid_gid();
    pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* Check if parent is tracked, if so track this child too */
    if (!bpf_map_lookup_elem(&tracked_pids, &ppid))
        return 0;

    /* Add this PID to tracked set */
    bpf_map_update_elem(&tracked_pids, &pid, &val, BPF_ANY);

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_EXEC;
    e->pid = pid;
    e->uid = (u32)uid_gid;
    e->ppid = ppid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->exit_code = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid, ppid;
    u64 id, uid_gid;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* Only trace process exits, not thread exits */
    if (pid != tid)
        return 0;

    /* Check if this PID is being tracked */
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return 0;

    uid_gid = bpf_get_current_uid_gid();

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->type = EVENT_EXIT;
    e->pid = pid;
    e->uid = (u32)uid_gid;

    ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->ppid = ppid;

    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    /* Remove from tracked set */
    bpf_map_delete_elem(&tracked_pids, &pid);

    return 0;
}
