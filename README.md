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
sudo ./sched_trace -- <command> [args...]
```

## Examples

```bash
sudo ./sched_trace -- bash -c 'grep -nIR xx /tmp/test'
sudo ./sched_trace -- sh -c 'ls | wc -l'
```

## Requirements

- Kernel with BTF support
- CAP_BPF capability or root privileges
- Go 1.25+
- clang/llvm (for BPF compilation via bpf2go)

