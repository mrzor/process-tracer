# go-ebpf-tracer

An eBPF-based process and network tracer with OpenTelemetry span integration.

Traces process execution trees and TCP connections, outputting structured logs with OpenTelemetry trace/span IDs for distributed tracing workflows.

## Quick Start

```bash
# Build
mise run go-build

# Run
sudo ./sched_trace -- <command>
```

## Features

- Process tree tracing with parent-child relationships
- TCP connection tracking (connect/close events)
- OpenTelemetry trace/span ID generation
- Automatic hostname resolution for TCP endpoints
- ISO8601 timestamps with nanosecond precision

## Requirements

- Linux kernel with BTF support
- CAP_BPF or root privileges
- Go 1.25+
- clang/llvm

## License

BSD 3-Clause - see LICENSE file

