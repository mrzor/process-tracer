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
- Custom span attributes (literal or dynamic via `expr:` prefix)
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
./process-tracer -t a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -- command ...

# Dynamic trace-id from environment (note the expr: prefix)
./process-tracer -t 'expr:env["TRACE_ID"]' -- echo hello

# When the value is not a valid 32-char hex trace id, it gets SHA-256'd
./process-tracer -t my-build-id-123 -- echo hello

# Set parent_id (defaults to no parent id)
./process-tracer -p 0123456789abcdef -- command ...

# Dynamic parent-id from environment
./process-tracer -p 'expr:env["PARENT_SPAN_ID"]' -- command ...

# Literal span attributes (the common case — no prefix needed)
./process-tracer -a service.name=my-service -a env=production -- command ...

# Dynamic attributes via expr: prefix
./process-tracer -a env_name='expr:env["ENVIRONMENT"]' -a pod='expr:env["POD_NAME"]' -- command ...

# Mix literal and dynamic
./process-tracer -a team=platform -a region='expr:env["AWS_REGION"]' -- command ...

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
| `PROCESS_TRACER_TRACE_ID` | `--trace-id` / `-t` | Trace ID: literal hex or `expr:EXPRESSION` |
| `PROCESS_TRACER_PARENT_ID` | `--parent-id` / `-p` | Parent span ID: literal hex or `expr:EXPRESSION` |
| `PROCESS_TRACER_ATTRIBUTES` | `-a` (repeated) | Semicolon-separated `NAME=VALUE` pairs (use `expr:` prefix for dynamic values) |
| `PROCESS_TRACER_MODE` | _(none)_ | Invocation mode: `auto` (default), `direct`, or `symlink` |
| `PROCESS_TRACER_SHELL_BINARY` | _(none)_ | Explicit path to the real shell binary (symlink mode only) |
| `PROCESS_TRACER_SHUTDOWN_TIMEOUT_MS` | _(none)_ | Max time in ms to flush remaining spans at exit (default: 200) |

```bash
export PROCESS_TRACER_TRACE_ID='expr:env["BUILD_ID"]'
export PROCESS_TRACER_PARENT_ID='expr:env["PARENT_SPAN"]'
export PROCESS_TRACER_ATTRIBUTES='env_name=expr:env["ENVIRONMENT"];region=expr:env["AWS_REGION"]'
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
export PROCESS_TRACER_TRACE_ID='expr:env["BUILD_ID"]'
export PROCESS_TRACER_ATTRIBUTES='ci.job=expr:env["CI_JOB_ID"]'

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

## Values and Expressions

All values (`-a`, `-t`, `-p` and their env var equivalents) are **literal by default**.
To evaluate a value dynamically at runtime, prefix it with `expr:`.

```bash
# Literal — used as-is
-a service.name=my-service
-t a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

# Expression — evaluated at runtime against the traced process
-a env_name='expr:env["ENVIRONMENT"]'
-t 'expr:env["TRACE_ID"]'
```

Expressions use the [expr](https://expr-lang.org/) language with these bindings:

| Binding    | Type                | Description |
|---|---|---|
| `env`      | `map[string]string` | Traced process environment variables |
| `args`     | `[]string`          | Traced process command-line arguments |
| `cmdline`  | `string`            | Full command line as a single string |

If an `expr:` expression fails to compile, it is warned and skipped (attributes)
or treated as unset (trace-id / parent-id). This tool never aborts on bad input.

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

