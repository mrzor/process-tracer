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

### TCP Connection Tracking

Tracks TCP connect/close events with OpenTelemetry span IDs, showing:
- Source/destination IPs and ports
- Connection duration
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

