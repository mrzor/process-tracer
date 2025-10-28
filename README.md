# Sched Trace - Go + cilium/ebpf

Process tree tracer using Go and cilium/ebpf package. Functionally identical to the C version.

## Project Structure

```
golang/
├── cmd/sched_trace/    # Main application
├── internal/bpf/       # BPF programs and Go bindings
├── go.mod
└── README.md
```

## Build

```bash
# Generate BPF Go bindings and build
mise run go-build

# Or step by step
mise run go-generate
mise run go-build

# Or use Go directly
go generate ./internal/bpf
go build -o sched_trace ./cmd/sched_trace
```

## Run

```bash
sudo ./sched_trace [--trace-id <id>] -- <command> [args...]
```

### Options

- `--trace-id <id>`: Specify an OpenTelemetry trace ID (32 hex chars). Auto-generates if not provided.

## Examples

```bash
# Basic process tree tracing
sudo ./sched_trace -- bash -c 'grep -nIR xx /tmp/test'
sudo ./sched_trace -- sh -c 'ls | wc -l'

# TCP connections automatically enriched with hostnames
sudo ./sched_trace -- curl https://example.com

# With custom trace ID
sudo ./sched_trace --trace-id 0123456789abcdef0123456789abcdef -- python script.py
```

## Features

### Span Tracking and Timestamps

Both process spans and TCP connection spans include:
- **ISO8601 timestamps**: `start_time` and `end_time` in RFC3339Nano format with nanosecond precision
- **Duration**: Elapsed time in nanoseconds (calculated from CLOCK_MONOTONIC for accuracy)
- **OpenTelemetry span IDs**: For distributed tracing correlation
- **Parent span relationships**: Hierarchical span tracking

**Example output:**
```
type=process pid=12345 ... start_time=2025-10-28T22:15:30.123456789Z end_time=2025-10-28T22:15:31.234567890Z duration=1111111101ns ...
type=tcp pid=12345 ... start_time=2025-10-28T22:15:30.500000000Z end_time=2025-10-28T22:15:30.750000000Z duration=250000000ns ...
```

### TCP Connection Tracking

Tracks TCP connect/close events with OpenTelemetry span IDs, showing:
- Source/destination IPs and ports
- ISO8601 start/end timestamps
- Connection duration (nanoseconds)
- Parent span relationships

### Pseudo Reverse DNS

The tracer automatically extracts network endpoints from:
- Process environment variables (DATABASE_URL, REDIS_HOST, API_ENDPOINT, etc.)
- Command-line arguments (useful for curl, wget, etc.)

This enriches TCP connection output with hostnames instead of just raw IPs. The system:
- Scans `/proc/<pid>/environ` and `/proc/<pid>/cmdline` for hostnames and IPs
- Resolves hostnames to IP addresses via DNS
- Builds reverse lookup maps for IP → hostname resolution
- Outputs `dest_host` and `src_host` fields in TCP events when matches are found

**Architecture:** Extensible design supports future dynamic sources (eBPF file reads, UDP packets, DNS responses) through `StaticSource` and `DynamicSource` interfaces.

## Requirements

- Kernel with BTF support
- CAP_BPF capability or root privileges
- Go 1.25+
- clang/llvm (for BPF compilation via bpf2go)

