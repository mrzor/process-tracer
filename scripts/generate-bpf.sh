#!/bin/bash
set -euo pipefail

# Detect architecture and map to bpf2go target
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        TARGET="amd64"
        ;;
    aarch64|arm64)
        TARGET="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

echo "Generating BPF code for $TARGET (detected: $ARCH)"
cd "$(dirname "$0")/../internal/bpf"
export GOPACKAGE=bpf
go run github.com/cilium/ebpf/cmd/bpf2go -target "$TARGET" processTracer ./process_tracer.bpf.c -- -I. -I/usr/include
