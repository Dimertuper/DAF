# NAT Detector

**Module:** `NATDetector` in `nat_detector.py`, a flow-based detector (`Detector`). In
windowed processing it runs in every window; an IP flagged in a window is not processed
in later windows.

This module detects potential NAT (Network Address Translation) devices. It analyzes flow records for each IP address and flags those that show a high number of unique TTL values and source ports — a common indicator of NATed traffic.

## Parameters

- `field` (`str`): Name of the field containing the TTL value.
- `min_unique_ttl` (`int`, optional): Minimal number of unique TTL values, default `5`.
- `min_unique_src_ports` (`int`, optional): Minimal number of unique source ports, default `500`.

The source port column is taken from `daf.src_port_field`.

```yaml
nat_detector:
  enabled: True
  path: auto
  field: "TTL"
  min_unique_ttl: 5
  min_unique_src_ports: 500
```

## Detection Criteria

An IP address is flagged if:
- It has at least `min_unique_ttl` unique TTL values (excluding 0), and
- It has at least `min_unique_src_ports` unique source ports (excluding 0)

The result (`detected`, `unique_ttl_values`, `unique_src_ports`) is stored in
`IP.data["nat_detector"]`. Positive results are added to `IP.multi_device` as
`NAT_detector` evidence.
