# process-tracer

An eBPF-based process and network tracer with OpenTelemetry span integration.

The quality bar is MEH and it will stay there until further notice.

This has been largely vibe-coded [1]. If you distrust outputs from coding agents, you might
want to read all the source-code. Alternatively, you're invited to try it: it mostly works.

Traces process execution trees and TCP connections, outputting structured logs with OpenTelemetry trace/span IDs for distributed tracing workflows.

Process-level tracing is generally not done for a reason that eludes me, and I believe I
need it, so here this is. The TCP thing is super rudimentary compared to any professional
alternative. It may or may not improve over time.

[1] This README was, however, written by an ape, as one would figure out from the lack of bullet points and surprising absence of emojis.

## Quick Start

```bash
# Build
mise run go-build

# Run
sudo ./process-tracer -- <command>
```

## Features

- Process tree tracing with parent-child relationships
- TCP connection tracking (connect/close events)
- OpenTelemetry trace/span ID generation
- Automatic hostname resolution for TCP endpoints (really hackish)

## Development

- Use [mise](https://github.com/jdx/mise)
- `mise trust && mise install`
- `mise go-build && mise setcap`

# Contributing

- Vibe-coded contributions welcome IFF:
  - Detailed commit messages
  - Extra tests are added
  - There is no duplication of existing functionality
  - I like it.

- Vibe-coded bug fixes are invited to follow a two-step commit process
  - First vibe-code reproduction testcase
  - Then vibe-code fix

- Applied software engineering to diminish the amount of vibe-coded nonsense is WELCOMED
  - PREFER: pure functions, immutability, command-query separation and state machines
  - AVOID: ye-old design pattern for manually allocated memory languages
  - AVOID: excessive DRY / exhaustive testing / YAGNI features
  - AVOID: dogmatism and blind rule-following

## Requirements

- Linux kernel with BTF support
- CAP_BPF or root privileges
- Go 1.25+
- clang/llvm

## License

BSD 3-Clause - see LICENSE file

