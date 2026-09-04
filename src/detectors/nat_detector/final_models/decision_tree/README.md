# NAT decision tree

This package contains the primary depth-8 decision-tree NAT classifier and its
reproducible training notebook.

## Files

- `nat_decision_tree_depth_8.joblib`: fitted `NATClassifier` artifact loaded by
  DAF.
- `train_nat_decision_tree.ipynb`: training, grouped train/test split,
  evaluation, serialization, and runtime-path verification.

| Metric | Value |
| --- | ---: |
| Accuracy | 0.8008 |
| F1 (NAT is positive) | 0.8210 |
| Recall (NAT is positive) | 0.9052 |

## Feature mapping

The artifact stores this ordered pandas named-aggregation mapping inside its
`NATClassifier` wrapper:

| Model feature | Raw flow column | Aggregation |
| --- | --- | --- |
| `source_port_count` | `SRC_PORT` | `nunique` |
| `destination_port_count` | `DST_PORT` | `nunique` |
| `tcp_syn_size_count` | `TCP_SYN_SIZE` | `nunique` |
| `tcp_window_count` | `TCP_WIN` | `nunique` |
| `ttl_count` | `IP_TTL` | `nunique` |
| `mean_ttl` | `IP_TTL` | `mean` |
| `mean_source_port` | `SRC_PORT` | `mean` |
| `mean_destination_port` | `DST_PORT` | `mean` |
| `total_bytes` | `BYTES` | `sum` |
| `total_reverse_bytes` | `BYTES_REV` | `sum` |
| `total_packets` | `PACKETS` | `sum` |
| `total_reverse_packets` | `PACKETS_REV` | `sum` |
| `flow_count` | `SRC_IP` | `size` |

The runtime flow table must therefore provide:

```text
SRC_IP, SRC_PORT, DST_PORT, TCP_SYN_SIZE, TCP_WIN, IP_TTL,
BYTES, BYTES_REV, PACKETS, PACKETS_REV
```

`NATClassifier.required_columns` exposes this raw schema. During detector
startup, the feature mapping checks that the corresponding input columns are
available.

## DAF configuration

When DAF is launched from the `src` directory:

```yaml
daf:
  windowing:
    enabled: true
    type: time
    size: 15min
    timestamp_field: TIME_FIRST
    consensus: majority

nat_detector:
  enabled: true
  path: auto
  model_path: ./detectors/nat_detector/final_models/decision_tree/nat_decision_tree_depth_8.joblib
  threshold: 0.5
  feature_mapping:
    SRC_IP: SRC_IP
    SRC_PORT: SRC_PORT
    DST_PORT: DST_PORT
    TCP_SYN_SIZE: TCP_SYN_SIZE
    TCP_WIN: TCP_WIN
    IP_TTL: IP_TTL
    BYTES: BYTES
    BYTES_REV: BYTES_REV
    PACKETS: PACKETS
    PACKETS_REV: PACKETS_REV
```

The runtime window size should match the 15-minute training boundary.
