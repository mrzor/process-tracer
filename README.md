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

# Set extra attributes from environment (using NAME=EXPR format)
./process-tracer -a extra.attribute.name='env["EXTRA_ATTR"]' -- command ...

# Multiple attributes
./process-tracer -a env_name='env["ENVIRONMENT"]' -a pod='env["POD_NAME"]' -- command ...

# Show help
./process-tracer --help
```

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
  - AVOID: mixing concerns, big packages

## Requirements

- Linux 5.17+ kernel with BTF support
- CAP_BPF or root privileges
- Go 1.25+
- clang/llvm

## License

BSD 3-Clause - see LICENSE file

