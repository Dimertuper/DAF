#!/usr/bin/env bash

# Run a standard TCP SYN scan with service and OS detection.
#
# Usage:
#   ./scan.sh [--dry-run] TARGET OUTPUT.xml
#
# Examples:
#   ./scan.sh 192.168.1.10 result.xml
#   ./scan.sh 192.168.1.0/24 network.xml
#   ./scan.sh --dry-run 192.168.1.10 result.xml
#
# Nmap options:
#   -sS                 TCP SYN scan
#   -sV                 Detect service versions
#   -O                  Detect operating system
#   -n                  Disable reverse DNS lookups
#   -T3                 Use moderate timing
#   --top-ports 1000    Scan the 1000 most common TCP ports
#   -oX                 Save results as XML

set -euo pipefail

dry_run=false

# Optional dry-run mode.
if [[ "${1:-}" == "--dry-run" ]]; then
    dry_run=true
    shift
fi

# Require exactly two arguments.
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 [--dry-run] TARGET OUTPUT.xml" >&2
    exit 2
fi

target="$1"
output="$2"

# Do not allow the target to look like an Nmap option.
if [[ "$target" == -* ]]; then
    echo "Error: TARGET must not start with '-'." >&2
    exit 2
fi

# Output must be a normal file path.
if [[ "$output" == -* ]]; then
    echo "Error: OUTPUT.xml must be a file path." >&2
    exit 2
fi

# Avoid accidentally replacing an existing scan.
if [[ -e "$output" ]]; then
    echo "Error: refusing to overwrite existing file: $output" >&2
    exit 1
fi

# Build the Nmap command.
nmap_command=(
    nmap
    -sS
    -sV
    -O
    -n
    -T3
    --top-ports 1000
    -oX "$output"
    "$target"
)

# Print the command instead of running it.
if "$dry_run"; then
    printf 'Command: '
    printf '%q ' "${nmap_command[@]}"
    printf '\n'
    exit 0
fi

# Make sure Nmap is installed.
if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: nmap is not installed or not available in PATH." >&2
    exit 127
fi

echo "Starting Nmap scan"
echo "Target: $target"
echo "Output: $output"
echo

exec "${nmap_command[@]}"