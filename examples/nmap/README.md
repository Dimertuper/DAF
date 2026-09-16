# Producing Nmap XML for DAF

OS detection and SYN/UDP scanning normally require privileges:

```sh
sudo ./scan_host.sh 192.168.10.10 host.xml
sudo ./scan_cidr.sh 192.168.10.0/24 subnet.xml 192.168.10.1
sudo ./scan_deep.sh 192.168.10.10 deep.xml
sudo ./scan_tcp_udp.sh 192.168.10.10 tcp-udp.xml
```

The baseline scripts scan TCP ports and combine `-sV` service detection with `-O` OS fingerprinting.
The deep scan covers all TCP ports and all version probes, so it can take substantially longer.
The TCP/UDP example also covers common DNS, DHCP, NTP, and SNMP ports.
Nmap normally skips version probes on TCP port 9100 because some printers print probe data.

IPv6 scanning requires `-6`, for example:

```sh
sudo nmap -6 -sS -sV -O -n -T3 --top-ports 1000 -oX ipv6.xml 2001:db8::10
```

Timing templates trade speed for reliability. These examples use the moderate `-T3`.
Options such as `--host-timeout` can bound slow scans, but a timed-out host has no port,
service, or OS table in the resulting XML.
