//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process_tracer.h"

char LICENSE[] SEC("license") = "GPL";

/* Address family constants */
#define AF_INET  2
#define AF_INET6 10

/* Error codes */
#define EINPROGRESS 115

/* Network byte order conversion */
#define bpf_ntohs(x) __builtin_bswap16(x)

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

/* Map to track active TCP connections */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // socket address
    __type(value, struct tcp_span_info);
} active_tcp_conns SEC(".maps");

/* Map to track in-flight connect() calls */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // pid_tgid
    __type(value, struct sock *);
} inflight_connects SEC(".maps");

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
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->data.proc.comm, sizeof(e->data.proc.comm));
    e->data.proc.exit_code = 0;

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
    e->timestamp = bpf_ktime_get_ns();

    ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->ppid = ppid;

    e->data.proc.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_get_current_comm(&e->data.proc.comm, sizeof(e->data.proc.comm));

    bpf_ringbuf_submit(e, 0);

    /* Remove from tracked set */
    bpf_map_delete_elem(&tracked_pids, &pid);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    /* Check if this PID is being tracked */
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return 0;

    /* Store socket for return probe */
    bpf_map_update_elem(&inflight_connects, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct sock **skpp, *sk;
    struct tcp_span_info span_info;
    struct event *e;
    u64 skaddr;
    u16 family, sport, dport;
    u32 saddr, daddr;

    /* Lookup stored socket */
    skpp = bpf_map_lookup_elem(&inflight_connects, &pid_tgid);
    if (!skpp)
        return 0;

    sk = *skpp;
    bpf_map_delete_elem(&inflight_connects, &pid_tgid);

    /* Check if connect succeeded (ret == 0 or -EINPROGRESS) */
    if (ret != 0 && ret != -EINPROGRESS)
        return 0;

    /* Extract connection info from sock struct */
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    skaddr = (u64)sk;

    /* Store in active connections map */
    span_info.start_time = bpf_ktime_get_ns();
    span_info.pid = pid;
    span_info.family = family;
    bpf_map_update_elem(&active_tcp_conns, &skaddr, &span_info, BPF_ANY);

    /* Emit TCP connect event */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TCP_CONNECT;
    e->pid = pid;
    e->ppid = 0;
    e->uid = (u32)bpf_get_current_uid_gid();
    e->timestamp = span_info.start_time;
    e->data.tcp.skaddr = skaddr;
    e->data.tcp.sport = sport;
    e->data.tcp.dport = dport;
    e->data.tcp.family = family;

    /* Read addresses - IPv4 only for tcp_v4_connect */
    saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    bpf_probe_read_kernel(e->data.tcp.saddr, 4, &saddr);
    bpf_probe_read_kernel(e->data.tcp.daddr, 4, &daddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect_entry, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    /* Check if this PID is being tracked */
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return 0;

    /* Store socket for return probe */
    bpf_map_update_elem(&inflight_connects, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_exit, int ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct sock **skpp, *sk;
    struct tcp_span_info span_info;
    struct event *e;
    u64 skaddr;
    u16 family, sport, dport;

    /* Lookup stored socket */
    skpp = bpf_map_lookup_elem(&inflight_connects, &pid_tgid);
    if (!skpp)
        return 0;

    sk = *skpp;
    bpf_map_delete_elem(&inflight_connects, &pid_tgid);

    /* Check if connect succeeded */
    if (ret != 0 && ret != -EINPROGRESS)
        return 0;

    /* Extract connection info */
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    skaddr = (u64)sk;

    /* Store in active connections map */
    span_info.start_time = bpf_ktime_get_ns();
    span_info.pid = pid;
    span_info.family = family;
    bpf_map_update_elem(&active_tcp_conns, &skaddr, &span_info, BPF_ANY);

    /* Emit TCP connect event */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TCP_CONNECT;
    e->pid = pid;
    e->ppid = 0;
    e->uid = (u32)bpf_get_current_uid_gid();
    e->timestamp = span_info.start_time;
    e->data.tcp.skaddr = skaddr;
    e->data.tcp.sport = sport;
    e->data.tcp.dport = dport;
    e->data.tcp.family = family;

    /* Read IPv6 addresses */
    bpf_probe_read_kernel(e->data.tcp.saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
    bpf_probe_read_kernel(e->data.tcp.daddr, 16, &sk->__sk_common.skc_v6_daddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct event *e;
    struct tcp_span_info *existing_span;
    u64 skaddr;
    u16 newstate, sport, dport;

    /* Read required fields */
    newstate = BPF_CORE_READ(ctx, newstate);
    skaddr = (__u64)BPF_CORE_READ(ctx, skaddr);
    sport = BPF_CORE_READ(ctx, sport);
    dport = BPF_CORE_READ(ctx, dport);

    /* Only handle TCP_CLOSE events now - connection tracking done in kprobes */
    if (newstate != TCP_CLOSE)
        return 0;

    /* Lookup existing connection */
    existing_span = bpf_map_lookup_elem(&active_tcp_conns, &skaddr);
    if (!existing_span)
        return 0;

    /* Emit TCP close event */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_tcp_conns, &skaddr);
        return 0;
    }

    e->type = EVENT_TCP_CLOSE;
    e->pid = existing_span->pid;
    e->ppid = 0;
    e->uid = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();

    e->data.tcp.skaddr = skaddr;
    e->data.tcp.sport = sport;
    e->data.tcp.dport = dport;
    e->data.tcp.family = existing_span->family;

    /* Copy addresses from context */
    if (existing_span->family == AF_INET) {
        bpf_probe_read_kernel(e->data.tcp.saddr, 4, &ctx->saddr);
        bpf_probe_read_kernel(e->data.tcp.daddr, 4, &ctx->daddr);
    } else {  /* AF_INET6 */
        bpf_probe_read_kernel(e->data.tcp.saddr, 16, &ctx->saddr_v6);
        bpf_probe_read_kernel(e->data.tcp.daddr, 16, &ctx->daddr_v6);
    }

    bpf_ringbuf_submit(e, 0);

    /* Remove from tracking map */
    bpf_map_delete_elem(&active_tcp_conns, &skaddr);

    return 0;
}
