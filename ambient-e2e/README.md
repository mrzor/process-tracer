# Ambient Mode E2E Test

Validates the ambient mode daemon (`process-tracer daemon`) in an isolated QEMU VM. The daemon attaches eBPF probes to **all** execs system-wide, so running it untested on a workstation is risky — this test boots a throwaway Debian 13 VM instead.

## Prerequisites

Host tools:

- `qemu-system-x86_64`, `qemu-img`
- `genisoimage`, `mkisofs`, or `xorrisofs` (any one)
- `uv`, `python3`
- `go` (1.24+)
- `curl`

KVM (`/dev/kvm` writable) is recommended but not required — without it the VM runs in full emulation and takes several minutes longer.

## Quick Start

```bash
cd ambient-e2e
./run-test.sh
```

First run downloads ~415 MB of dependencies (Debian cloud image + otelcol-contrib) into `.cache/`, which is reused on subsequent runs.

## What Happens

1. **Host** builds a static `process-tracer` binary.
2. **Host** stages files into `staging/` and starts an HTTP server + OTLP collector.
3. **Host** boots a QEMU VM with a cloud-init ISO and copy-on-write overlay.
4. **VM** (via cloud-init) installs `make`, downloads test files from the host HTTP server.
5. **VM** runs the daemon (sends OTLP traces to host collector at `10.0.2.2:4318`).
6. **VM** runs `make -f Makefile.test` — a workload that spawns nested child processes.
7. **VM** waits for traces to flush, stops the daemon, and powers off.
8. **Host** stops the collector and runs `verify-traces.sh` to assert that expected spans exist.

Communication between host and VM uses QEMU user-mode networking (host is `10.0.2.2` from guest). Files are served via HTTP, traces flow via OTLP/HTTP.

## Configuration

| File | Purpose |
|------|---------|
| `ambient-test.yaml` | Daemon config — rules, OTEL endpoint, limits |
| `otelcol.yaml` | Collector config — OTLP receiver, file exporter |
| `Makefile.test` | Workload that triggers tracing |

The default rule matches processes with comm `make` and tags spans with `service.name: ambient-e2e`.

## Troubleshooting

On failure, `staging/serial.log` contains the VM's console output (cloud-init progress, daemon logs). Comment out `rm -rf "$STAGING"` in `run-test.sh` to preserve it.

**Common failures:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `qemu-system-x86_64: not found` | QEMU not installed | `sudo pacman -S qemu-full` / `apt install qemu-system-x86` |
| VM boot very slow (>5 min) | No KVM | Ensure `/dev/kvm` exists and is writable |
| Collector not ready | Port conflict | Check nothing else uses port 4318 |
| No spans in traces.jsonl | Daemon didn't attach probes | Check serial.log for BPF errors |
| `verify-traces.sh` fails on service.name | Rule didn't match | Check `ambient-test.yaml` command field matches kernel comm |
