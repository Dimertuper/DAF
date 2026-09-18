#!/usr/bin/env bash

# Run an Nmap SYN, service, and OS detection scan against an IPv4 CIDR.
#
# Usage:
#   ./scan_cidr.sh [--dry-run] CIDR OUTPUT.xml [EXCLUDE]
#
# Examples:
#   ./scan_cidr.sh 192.168.1.0/24 subnet.xml
#   ./scan_cidr.sh 192.168.1.0/24 subnet.xml 192.168.1.1
#   ./scan_cidr.sh --dry-run 192.168.1.0/24 subnet.xml
#
# Options:
#   --dry-run   Print the Nmap command without executing it.
#
# EXCLUDE is optional and is passed directly to Nmap's --exclude option.

set -euo pipefail

dry_run=false

# Handle optional --dry-run flag.
if [[ "${1:-}" == "--dry-run" ]]; then
    dry_run=true
    shift
fi

# Validate the number of arguments.
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 [--dry-run] CIDR OUTPUT.xml [EXCLUDE]" >&2
    exit 2
fi

target="$1"
output="$2"
exclude="${3:-}"

# Basic target validation.
if [[ "$target" != */* || "$target" == -* ]]; then
    echo "Error: CIDR must look like 192.168.1.0/24" >&2
    exit 2
fi

# Prevent OUTPUT.xml from being interpreted as an Nmap option.
if [[ "$output" == -* ]]; then
    echo "Error: OUTPUT.xml must be a file path." >&2
    exit 2
fi

# Avoid accidentally replacing an existing scan.
if [[ -e "$output" ]]; then
    echo "Error: output file already exists: $output" >&2
    exit 1
fi

# Build the Nmap command.
nmap_command=(
    nmap
    -sS                # TCP SYN scan
    -sV                # Service/version detection
    -O                 # OS detection
    -n                 # Do not perform reverse DNS lookups
    -T3                # Moderate timing
    --top-ports 1000   # Scan the 1000 most common ports
)

# Add excluded hosts/networks if requested.
if [[ -n "$exclude" ]]; then
    nmap_command+=(--exclude "$exclude")
fi

# XML output and target.
nmap_command+=(
    -oX "$output"
    "$target"
)

# In dry-run mode, just show what would be executed.
if "$dry_run"; then
    printf 'Command: '
    printf '%q ' "${nmap_command[@]}"
    printf '\n'
    exit 0
fi

# Check that Nmap is installed before trying to run it.
if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: nmap is not installed or not available in PATH." >&2
    exit 127
fi

echo "Scanning: $target"
echo "Output:   $output"

if [[ -n "$exclude" ]]; then
    echo "Exclude:  $exclude"
fi

echo

exec "${nmap_command[@]}"
