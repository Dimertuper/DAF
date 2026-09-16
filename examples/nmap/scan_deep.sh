#!/usr/bin/env bash

# Run a full TCP port scan with detailed service and OS detection.
#
# Usage:
#   ./scan-full.sh [--dry-run] TARGET OUTPUT.xml
#
# Examples:
#   ./scan-full.sh 192.168.1.10 host.xml
#   ./scan-full.sh 192.168.1.0/24 network.xml
#   ./scan-full.sh --dry-run 192.168.1.10 host.xml
#
# Scan options:
#   -sS            TCP SYN scan
#   -sV            Service/version detection
#   --version-all  Try all available service probes
#   -O             OS detection
#   -n             Disable reverse DNS lookups
#   -T3            Moderate scan timing
#   -p-            Scan all 65,535 TCP ports
#   -oX            Write results as XML

set -euo pipefail

dry_run=false

# Handle optional dry-run mode.
if [[ "${1:-}" == "--dry-run" ]]; then
    dry_run=true
    shift
fi

# Exactly two arguments are required after processing --dry-run.
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 [--dry-run] TARGET OUTPUT.xml" >&2
    exit 2
fi

target="$1"
output="$2"

# Prevent TARGET from being interpreted as an Nmap option.
if [[ "$target" == -* ]]; then
    echo "Error: TARGET must not start with '-'." >&2
    exit 2
fi

# Prevent OUTPUT.xml from being interpreted as an option.
if [[ "$output" == -* ]]; then
    echo "Error: OUTPUT.xml must be a file path." >&2
    exit 2
fi

# Avoid overwriting an existing scan.
if [[ -e "$output" ]]; then
    echo "Error: refusing to overwrite existing file: $output" >&2
    exit 1
fi

# Build the Nmap command.
nmap_command=(
    nmap
    -sS
    -sV
    --version-all
    -O
    -n
    -T3
    -p-
    -oX "$output"
    "$target"
)

# In dry-run mode, print the command without executing it.
if "$dry_run"; then
    printf 'Command: '
    printf '%q ' "${nmap_command[@]}"
    printf '\n'
    exit 0
fi

# Check that Nmap is available.
if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: nmap is not installed or not available in PATH." >&2
    exit 127
fi

echo "Starting full TCP scan"
echo "Target: $target"
echo "Output: $output"
echo

exec "${nmap_command[@]}"