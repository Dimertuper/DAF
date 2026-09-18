#!/usr/bin/env bash

# Run a targeted TCP + UDP scan with service and OS detection.
#
# Usage:
#   ./scan-targeted.sh [--dry-run] TARGET OUTPUT.xml
#
# Examples:
#   ./scan-targeted.sh 192.168.1.10 result.xml
#   ./scan-targeted.sh 192.168.1.0/24 network.xml
#   ./scan-targeted.sh --dry-run 192.168.1.10 result.xml
#
# Nmap options:
#   -sS    TCP SYN scan
#   -sU    UDP scan
#   -sV    Service/version detection
#   -O     OS detection
#   -n     Disable reverse DNS lookups
#   -T3    Moderate timing
#
# TCP ports:
#   22    SSH
#   25    SMTP
#   53    DNS
#   80    HTTP
#   110   POP3
#   143   IMAP
#   443   HTTPS
#   445   SMB
#   587   SMTP submission
#   993   IMAPS
#   995   POP3S
#   8080  Alternate HTTP
#   8443  Alternate HTTPS
#
# UDP ports:
#   53    DNS
#   67    DHCP server
#   68    DHCP client
#   123   NTP
#   161   SNMP

set -euo pipefail

dry_run=false

# Enable dry-run mode if requested.
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

# Prevent the target from being interpreted as an Nmap option.
if [[ "$target" == -* ]]; then
    echo "Error: TARGET must not start with '-'." >&2
    exit 2
fi

# Output must be a normal file path.
if [[ "$output" == -* ]]; then
    echo "Error: OUTPUT.xml must be a file path." >&2
    exit 2
fi

# Avoid accidentally overwriting an existing scan.
if [[ -e "$output" ]]; then
    echo "Error: refusing to overwrite existing file: $output" >&2
    exit 1
fi

tcp_ports="22,25,53,80,110,143,443,445,587,993,995,8080,8443"
udp_ports="53,67,68,123,161"

ports="T:${tcp_ports},U:${udp_ports}"

# Build the Nmap command.
nmap_command=(
    nmap
    -sS
    -sU
    -sV
    -O
    -n
    -T3
    -p "$ports"
    -oX "$output"
    "$target"
)

# Print the command without running it.
if "$dry_run"; then
    printf 'Command: '
    printf '%q ' "${nmap_command[@]}"
    printf '\n'
    exit 0
fi

# Make sure Nmap is available.
if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: nmap is not installed or not available in PATH." >&2
    exit 127
fi

echo "Starting targeted TCP/UDP scan"
echo "Target:    $target"
echo "TCP ports: $tcp_ports"
echo "UDP ports: $udp_ports"
echo "Output:    $output"
echo

exec "${nmap_command[@]}"