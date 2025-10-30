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

/* Maximum size for a single environment variable or argument */
#define MAX_ENV_VALUE_SIZE 2048

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);  /* 2MB for streaming env vars */
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

/* Map to track in-flight execve calls
 * We send env/argv data immediately in sys_enter_execve
 * This map just tracks which PIDs have entered execve for cleanup
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // pid_tgid
    __type(value, u8);  // just a marker
} inflight_execve SEC(".maps");

/* Per-CPU buffer for environment variable temporary storage */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ENV_VALUE_SIZE]);
} env_var_buffer SEC(".maps");

/* State tracking for streaming env vars with tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);  /* Track up to 1024 concurrent execve */
    __type(key, u32);            /* PID */
    __type(value, struct env_stream_state);
} env_stream_state_map SEC(".maps");

/* Program array for tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} prog_array SEC(".maps");

/* Context for bpf_loop() callbacks */
struct loop_ctx {
    char **arr_ptr;         /* argv or envp pointer */
    struct env_chunk_event *chunk;
    char *var_buf;
    u32 *offset_ptr;
    u32 *count_ptr;         /* argc or NULL for envp */
    u32 max_var_size;
    u32 done;               /* Set to 1 to stop iteration */
};

/* Callback for bpf_loop() to read one argv/envp entry */
static long read_var_callback(u32 index, void *ctx)
{
    struct loop_ctx *lctx = (struct loop_ctx *)ctx;
    char *var_ptr = NULL;
    int var_len;
    u32 offset = *lctx->offset_ptr;
    u32 max_size = lctx->max_var_size;

    /* Check if we should stop (previous iteration hit NULL or limit) */
    if (lctx->done)
        return 1; /* Stop iteration */

    /* Verify max_size is bounded for verifier (must match env_var_buffer size) */
    if (max_size > MAX_ENV_VALUE_SIZE)
        max_size = MAX_ENV_VALUE_SIZE;

    /* Read pointer to variable */
    if (bpf_probe_read_user(&var_ptr, sizeof(var_ptr), &lctx->arr_ptr[index]))
        return 1; /* Stop on error */

    if (!var_ptr) {
        lctx->done = 1; /* NULL = end of array */
        return 1;
    }

    /* Read the variable string with bounded size */
    var_len = bpf_probe_read_user_str(lctx->var_buf, max_size, var_ptr);
    if (var_len <= 0)
        return 0; /* Continue to next */

    /* Bounds check for var_len */
    if (var_len > max_size)
        var_len = max_size;
    
    /* Explicit bounds check for offset - ensure we have room for max_size bytes */
    if (offset >= MAX_ENV_CHUNK_SIZE - MAX_ENV_VALUE_SIZE) {
        lctx->done = 1;
        return 1; /* Stop - not enough room for even one more var */
    }
    
    /* Final safety check: ensure var_len is absolutely bounded */
    if (var_len > MAX_ENV_VALUE_SIZE)
        var_len = MAX_ENV_VALUE_SIZE;
    
    /* Ensure we don't exceed buffer - clamp var_len if needed */
    if (offset + var_len > MAX_ENV_CHUNK_SIZE) {
        var_len = MAX_ENV_CHUNK_SIZE - offset;
    }
    
    /* Bounds check again after clamping */
    if (var_len > MAX_ENV_VALUE_SIZE)
        var_len = MAX_ENV_VALUE_SIZE;
    if (var_len <= 0) {
        lctx->done = 1;
        return 1;
    }
    
    /* Copy to chunk - verifier knows: offset < MAX_ENV_CHUNK_SIZE-MAX_ENV_VALUE_SIZE and var_len <= MAX_ENV_VALUE_SIZE */
    /* Therefore: offset + var_len < MAX_ENV_CHUNK_SIZE */
    if (var_len > 0 && var_len <= MAX_ENV_VALUE_SIZE) {
        bpf_probe_read_kernel(&lctx->chunk->data[offset], var_len, lctx->var_buf);
    }

    offset += var_len;
    *lctx->offset_ptr = offset;
    
    /* Increment argc if this is argv */
    if (lctx->count_ptr)
        (*lctx->count_ptr)++;

    return 0; /* Continue to next iteration */
}

/* Send environment/argv in single chunk using bpf_loop() for efficiency
 * This uses bpf_loop() (Linux 5.17+) which only verifies the callback once,
 * allowing us to support many more variables without instruction explosion.
 */
static __always_inline void send_env_multi_chunk(u32 pid, u64 argv_addr, u64 envp_addr)
{
    struct env_chunk_event *chunk;
    char **argv = (char **)argv_addr;
    char **envp = (char **)envp_addr;
    u32 offset = 0;
    u32 zero = 0;
    char *var_buf;
    struct loop_ctx ctx = {0};

    #define MAX_SIMPLE_ARGS 128
    #define MAX_SIMPLE_ENV 512   /* Try 256 env vars with bpf_loop() */
    #define MAX_VAR_SIZE MAX_ENV_VALUE_SIZE

    var_buf = bpf_map_lookup_elem(&env_var_buffer, &zero);
    if (!var_buf)
        return;

    chunk = bpf_ringbuf_reserve(&rb, sizeof(*chunk), 0);
    if (!chunk)
        return;

    chunk->pid = pid;
    chunk->ppid = 0;
    chunk->uid = 0;
    chunk->_pad1 = 0;
    chunk->timestamp = 0;
    chunk->type = EVENT_EXEC_ENV_CHUNK;
    chunk->chunk_id = 0;
    chunk->is_final = 1;
    chunk->truncated = 1;
    chunk->argc = 0;

    /* Read command-line arguments using bpf_loop() */
    ctx.arr_ptr = argv;
    ctx.chunk = chunk;
    ctx.var_buf = var_buf;
    ctx.offset_ptr = &offset;
    ctx.count_ptr = &chunk->argc;
    ctx.max_var_size = MAX_VAR_SIZE;
    ctx.done = 0;
    
    bpf_loop(MAX_SIMPLE_ARGS, read_var_callback, &ctx, 0);

    /* Read environment variables using bpf_loop() */
    ctx.arr_ptr = envp;
    ctx.count_ptr = NULL; /* Don't count env vars in argc */
    ctx.done = 0;
    
    bpf_loop(MAX_SIMPLE_ENV, read_var_callback, &ctx, 0);

    chunk->data_size = offset;
    bpf_ringbuf_submit(chunk, 0);

    #undef MAX_SIMPLE_ARGS
    #undef MAX_SIMPLE_ENV
    #undef MAX_VAR_SIZE
}

/* Simplified helper to send argv and env vars in a single chunk
 * This is much simpler for the verifier to validate
 * Format: argv vars followed by env vars, all as null-terminated strings
 * NOTE: This is the OLD implementation, kept for reference/fallback
 */
static __always_inline void send_process_args_and_env(u32 pid, u64 argv_addr, u64 envp_addr)
{
    struct env_chunk_event *chunk;
    char **argv = (char **)argv_addr;
    char **envp = (char **)envp_addr;
    u32 offset = 0;
    u32 zero = 0;
    char *var_buf;

    #define MAX_SIMPLE_ARGS 8   /* Capture first 8 command-line args */
    #define MAX_SIMPLE_ENV 4    /* Capture first 4 env vars */
    #define MAX_VAR_SIZE 256

    /* Get per-CPU buffer once */
    var_buf = bpf_map_lookup_elem(&env_var_buffer, &zero);
    if (!var_buf)
        return;

    /* Reserve single chunk */
    chunk = bpf_ringbuf_reserve(&rb, sizeof(*chunk), 0);
    if (!chunk)
        return;

    chunk->pid = pid;
    chunk->ppid = 0;      /* Not used */
    chunk->uid = 0;       /* Not used */
    chunk->_pad1 = 0;     /* Padding */
    chunk->timestamp = 0; /* Not used */
    chunk->type = EVENT_EXEC_ENV_CHUNK;
    chunk->chunk_id = 0;
    chunk->is_final = 1;  /* Single chunk only */
    chunk->truncated = 1;  /* Mark as truncated since we only get first few */
    chunk->argc = 0;      /* Will count as we read argv */

    /* First, read command-line arguments */
    #pragma unroll
    for (int i = 0; i < MAX_SIMPLE_ARGS; i++) {
        char *arg_ptr = NULL;
        int arg_len;

        /* Read pointer to arg */
        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]))
            break;  /* Failed to read pointer */

        if (!arg_ptr)
            break;  /* NULL = end of argv */

        /* Read the argument string */
        arg_len = bpf_probe_read_user_str(var_buf, MAX_VAR_SIZE, arg_ptr);
        if (arg_len <= 0)
            continue;  /* Skip failed reads */

        /* Bounds check */
        if (arg_len > MAX_VAR_SIZE)
            arg_len = MAX_VAR_SIZE;
        if (offset + arg_len > MAX_ENV_CHUNK_SIZE)
            break;  /* No more room */

        /* Simple copy with explicit bounds for verifier safety */
        for (int j = 0; j < MAX_VAR_SIZE; j++) {
            if (j >= arg_len)
                break;
            if (offset + j >= MAX_ENV_CHUNK_SIZE)
                break;
            chunk->data[offset + j] = var_buf[j];
        }

        offset += arg_len;
        chunk->argc++;  /* Count this arg */
    }

    /* Then, read environment variables */
    #pragma unroll
    for (int i = 0; i < MAX_SIMPLE_ENV; i++) {
        char *env_var_ptr = NULL;
        int var_len;

        /* Read pointer to env variable */
        if (bpf_probe_read_user(&env_var_ptr, sizeof(env_var_ptr), &envp[i]))
            break;  /* Failed to read pointer */

        if (!env_var_ptr)
            break;  /* NULL = end of array */

        /* Read the environment variable string */
        var_len = bpf_probe_read_user_str(var_buf, MAX_VAR_SIZE, env_var_ptr);
        if (var_len <= 0)
            continue;  /* Skip failed reads */

        /* Bounds check */
        if (var_len > MAX_VAR_SIZE)
            var_len = MAX_VAR_SIZE;
        if (offset + var_len > MAX_ENV_CHUNK_SIZE)
            break;  /* No more room */

        /* Simple copy with explicit bounds for verifier safety */
        for (int j = 0; j < MAX_VAR_SIZE; j++) {
            if (j >= var_len)
                break;
            if (offset + j >= MAX_ENV_CHUNK_SIZE)
                break;
            chunk->data[offset + j] = var_buf[j];
        }

        offset += var_len;
    }

    chunk->data_size = offset;
    bpf_ringbuf_submit(chunk, 0);

    #undef MAX_SIMPLE_ARGS
    #undef MAX_SIMPLE_ENV
    #undef MAX_VAR_SIZE
}

SEC("tp/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 argv_addr, envp_addr;
    u8 val = 1;

    /* Capture argv and envp pointers from syscall arguments
     * args[0] = filename
     * args[1] = argv
     * args[2] = envp
     */
    argv_addr = ctx->args[1];
    envp_addr = ctx->args[2];

    /* Read argv and envp NOW, while the old address space is still valid
     * This must happen BEFORE exec completes and switches address spaces
     *
     * NEW APPROACH: Send multiple chunks (8 chunks × 32 vars = 256 env vars)
     * This is within verifier limits and handles most cloud-native workloads
     */
    if (argv_addr && envp_addr) {
        send_env_multi_chunk(pid, argv_addr, envp_addr);
    }

    /* Mark that we've seen this execve (to match with sched_process_exec later) */
    bpf_map_update_elem(&inflight_execve, &pid_tgid, &val, BPF_ANY);

    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, ppid;
    u64 pid_tgid, uid_gid;
    u8 val = 1;

    uid_gid = bpf_get_current_uid_gid();
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

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

    /* Clean up the inflight_execve marker if it exists
     * Note: argv/env data was already sent in sys_enter_execve
     * before the address space switch
     */
    bpf_map_delete_elem(&inflight_execve, &pid_tgid);

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
