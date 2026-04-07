#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/.cache"
mkdir -p "$CACHE_DIR"

DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
DEBIAN_FILE="$CACHE_DIR/debian-13-genericcloud-amd64.qcow2"

OTELCOL_VERSION="0.149.0"
OTELCOL_URL="https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTELCOL_VERSION}/otelcol-contrib_${OTELCOL_VERSION}_linux_amd64.tar.gz"
OTELCOL_FILE="$CACHE_DIR/otelcol-contrib"

fetch_debian() {
    if [[ -f "$DEBIAN_FILE" ]]; then
        local size
        size=$(stat -c%s "$DEBIAN_FILE" 2>/dev/null || stat -f%z "$DEBIAN_FILE" 2>/dev/null)
        if (( size > 100000000 )); then
            echo "[fetch] Debian image cached ($(( size / 1048576 )) MB)"
            return 0
        fi
        echo "[fetch] Debian image looks truncated, re-downloading"
        rm -f "$DEBIAN_FILE"
    fi
    echo "[fetch] Downloading Debian 13 nocloud image..."
    curl -L -C - -o "$DEBIAN_FILE" "$DEBIAN_URL"
}

fetch_otelcol() {
    if [[ -x "$OTELCOL_FILE" ]]; then
        echo "[fetch] otelcol-contrib cached"
        return 0
    fi
    echo "[fetch] Downloading otelcol-contrib v${OTELCOL_VERSION}..."
    local tmptar="$CACHE_DIR/otelcol-contrib.tar.gz"
    curl -L -C - -o "$tmptar" "$OTELCOL_URL"
    tar -xzf "$tmptar" -C "$CACHE_DIR" otelcol-contrib
    chmod +x "$OTELCOL_FILE"
    rm -f "$tmptar"
}

fetch_debian
fetch_otelcol
echo "[fetch] All dependencies ready"
