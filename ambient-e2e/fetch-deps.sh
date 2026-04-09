#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/.cache"
mkdir -p "$CACHE_DIR"

if [[ -t 1 ]]; then
    DIM='\033[2m' BOLD='\033[1m' GREEN='\033[32m' RESET='\033[0m'
else
    DIM='' BOLD='' GREEN='' RESET=''
fi

log() { echo -e "${DIM}[host/fetch]${RESET} $1"; }
ok()  { echo -e "${GREEN}${BOLD}[host/fetch]${RESET} $1"; }

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
            ok "Debian image cached ($(( size / 1048576 )) MB)"
            return 0
        fi
        log "Debian image looks truncated, re-downloading"
        rm -f "$DEBIAN_FILE"
    fi
    log "Downloading Debian 13 genericcloud image..."
    curl -L -C - -o "$DEBIAN_FILE" "$DEBIAN_URL"
}

fetch_otelcol() {
    if [[ -x "$OTELCOL_FILE" ]]; then
        ok "otelcol-contrib cached"
        return 0
    fi
    log "Downloading otelcol-contrib v${OTELCOL_VERSION}..."
    local tmptar="$CACHE_DIR/otelcol-contrib.tar.gz"
    curl -L -C - -o "$tmptar" "$OTELCOL_URL"
    tar -xzf "$tmptar" -C "$CACHE_DIR" otelcol-contrib
    chmod +x "$OTELCOL_FILE"
    rm -f "$tmptar"
}

fetch_debian
fetch_otelcol
ok "All dependencies ready"
