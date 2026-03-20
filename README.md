# process-tracer

An eBPF-based process and network otel-tracer.

The quality bar is MEH and it's unlikely to significantly improve.

This has been largely vibe-coded [1]. If you distrust outputs from coding agents, you might
want to read all the source-code. Alternatively, you're invited to try it: it mostly works.

Process-level tracing is generally not done for a reason that eludes me, and I believe I
need it, so here this is. The TCP thing is super rudimentary compared to any professional
alternative.

[1] This README was, however, written by an ape, as one would figure out from the lack of
bullet points and surprising absence of emojis.

## Key Features

- Process tree tracing with parent-child relationships
- TCP connection tracking (connect/close events)
- Rudimentary hackish pseudo reverse-DNS system
- Expr expressions can be used to add extra attributes to spans
- Beware: process environment variable count is limited, and values are truncated after 2048 bytes

## Quick Start

```bash
# Build yourself
git clone ... && mise go-build

# Or just grab the latest build
mise use ubi:mrzor/process-tracer@latest

# Run
sudo ./process-tracer -- command ...

# Alternative
sudo mise setcap
./process-tracer -- command ...

# Set trace_id (defaults to a random one)
./process-tracer --trace-id a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -- command ...

# Or use short form
./process-tracer -t a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -- command ...

# expr-based trace-id
./process-tracer -t 'env["TRACE_ID"]' -- echo hello

# When the expression does not evaluate to a valid trace id, it will be
# SHA-256'd to transmute it into one
./process-tracer -t 'env["SHORT_ID"]' -- echo hello

# Set parent_id (defaults to no parent id)
./process-tracer --parent-id 0123456789abcdef -- command ...

# Or use expr-based parent-id
./process-tracer -p 'env["PARENT_SPAN_ID"]' -- command ...

# Set extra attributes from environment (using NAME=EXPR format)
./process-tracer -a extra.attribute.name='env["EXTRA_ATTR"]' -- command ...

# Multiple attributes
./process-tracer -a env_name='env["ENVIRONMENT"]' -a pod='env["POD_NAME"]' -- command ...

# Show help
./process-tracer --help
```

## Running a quick demo / testbed

A little shellscript is provided as a sample workload.
- Assuming you got the `mise` setup fully done, and you have a build (either downloaded, or built on your own)
- `otel-tui --http 8080` in a dedicated terminal
- `./process-tracer -- ./sample-workload.sh`
- In OTel TUI, navigate to the single trace you should be able to see the produced spans as well as their attributes. 

<!-- *AI SLOP* -->

## Environment Variables

All CLI flags have environment variable equivalents. CLI flags take precedence.

| Variable | Equivalent flag | Description |
|---|---|---|
| `PROCESS_TRACER_TRACE_ID` | `--trace-id` / `-t` | Expression for the OpenTelemetry trace ID |
| `PROCESS_TRACER_PARENT_ID` | `--parent-id` / `-p` | Expression for the OpenTelemetry parent span ID |
| `PROCESS_TRACER_ATTRIBUTES` | `-a` (repeated) | Semicolon-separated `NAME=EXPR` pairs |
| `PROCESS_TRACER_MODE` | _(none)_ | Invocation mode: `auto` (default), `direct`, or `symlink` |
| `PROCESS_TRACER_SHELL_BINARY` | _(none)_ | Explicit path to the real shell binary (symlink mode only) |

```bash
export PROCESS_TRACER_TRACE_ID='env["BUILD_ID"]'
export PROCESS_TRACER_PARENT_ID='env["PARENT_SPAN"]'
export PROCESS_TRACER_ATTRIBUTES='env_name=env["ENVIRONMENT"];region=env["AWS_REGION"]'
./process-tracer -- command ...
```

### OpenTelemetry Exporter

The OTLP/HTTP exporter is configured via standard OTEL environment variables. Some are parsed
by process-tracer, others are handled natively by the `otlptracehttp` library.

| Variable | Default | Description |
|---|---|---|
| `OTEL_SERVICE_NAME` | `sched_trace` | Service name in exported spans |
| `OTEL_RESOURCE_ATTRIBUTES` | _(none)_ | Comma-separated `key=value` resource attributes |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4318` | Endpoint URL or `host:port`. Supports `http://` and `https://` schemes |
| `OTEL_EXPORTER_OTLP_INSECURE` | _(auto)_ | `true` to force plain HTTP, `false` to force HTTPS. Auto-detects from endpoint scheme and localhost |

The following are passed through to the OTEL SDK and take effect without any process-tracer code:

| Variable | Description |
|---|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Traces-specific endpoint (overrides `OTEL_EXPORTER_OTLP_ENDPOINT`) |
| `OTEL_EXPORTER_OTLP_HEADERS` | Request headers (`key1=value1,key2=value2`) |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Export timeout in ms (default: 10000) |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | `gzip` to enable compression |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | Path to server CA certificate for TLS verification |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE` | Path to client certificate for mTLS |
| `OTEL_EXPORTER_OTLP_CLIENT_KEY` | Path to client private key for mTLS |

All `_TRACES_`-suffixed variants (e.g. `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT`) take precedence
over their base counterparts and are also supported by the library.

TLS is enabled by default for non-localhost endpoints. For local development with a collector
on `localhost`, plain HTTP is used automatically.

## Symlink Mode

process-tracer has two invocation modes: **direct** (the normal `process-tracer -- command` form)
and **symlink**. In symlink mode, you symlink the process-tracer binary under the name of the
shell or command you want to wrap. process-tracer then acts as a transparent drop-in replacement:
it forwards all arguments to the real binary while tracing the process tree.

This is useful when you can't easily change how a command is invoked (e.g. a CI system
hardcodes `/usr/local/bin/bash`) but you still want tracing.

```bash
# Create a symlink named "bash" pointing to process-tracer
ln -s /usr/local/bin/process-tracer /usr/local/bin/bash-traced
# Or, more aggressively:
# ln -sf /usr/local/bin/process-tracer /usr/local/bin/bash

# Configure via environment (CLI flags are NOT available in symlink mode)
export PROCESS_TRACER_TRACE_ID='env["BUILD_ID"]'
export PROCESS_TRACER_ATTRIBUTES='ci.job=env["CI_JOB_ID"]'

# Invocation looks exactly like the real shell — no "--" needed
./bash-traced -c 'npm test'
```

**How it works:**

1. On startup, process-tracer compares `os.Args[0]` (the invoked name) against its own
   executable path. If they differ after resolving symlinks, symlink mode activates.
2. It finds the real binary by searching `PATH` for a match with the symlink's basename,
   skipping itself. If nothing is found on `PATH`, it tries `/bin`, `/usr/bin`, and
   `/usr/local/bin`.
3. All arguments are forwarded as-is to the real binary.

**Forcing a mode:** Set `PROCESS_TRACER_MODE` to `direct` or `symlink` to skip auto-detection.
This can be handy if auto-detection gets confused (e.g. hardlinks instead of symlinks).

**Overriding shell resolution:** If the automatic lookup picks the wrong binary, set
`PROCESS_TRACER_SHELL_BINARY` to the absolute path of the real one.

<!-- */AI SLOP* -->

## Expressions

The `-a` flag accepts any valid [expr](https://expr-lang.org/) expression.

The process environment is bound to `env`, the full commandline to `cmdline` and
individual commandline atoms to `args`.

This gives you some flexibility if you're integrating in some CI environment,
convoluted build system and whatnot.

Note: The `--trace-id` / `-t` flag expects a 32-character hexadecimal string (128-bit trace ID),
not an expression.

## Development

- Use [mise](https://github.com/jdx/mise)
- You will need extra system packages, like `clang`, `llvm` and `bpftools`
- `mise trust && mise install`
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/bpf/vmlinux.h`
- `mise go-generate` (Repeat this step whenever `process_tracer.bpf.c` changes)
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
  - PREFER: pure functions, immutability, documented small-scoped packages, command-query separation and state machines
  - AVOID: mixing concerns, big packages

## Requirements

- Linux 5.17+ kernel with BTF support
- CAP_BPF or root privileges
- Go 1.25+
- clang/llvm

## License

BSD 3-Clause - see LICENSE file

