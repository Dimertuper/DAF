# Basic NAT decision tree

This package is an intentionally restricted baseline. The model is a decision
tree that uses only `IP_TTL` and `DST_PORT` from the raw flow table. Its
`max_depth` is selected from 3, 4, and 5 by grouped cross-validation on the
training partition; depth 3 was selected.

## Files

- `nat_basic_tree.joblib`: fitted `NATClassifier` artifact.
- `train_nat_basic_tree.ipynb`: training and evaluation notebook.

Held-out test results:

| Metric | Value |
| --- | ---: |
| Accuracy | 0.5871 |
| F1 (NAT is positive) | 0.5275 |
| Recall (NAT is positive) | 0.4569 |

## Feature mapping

| Model feature | Raw flow column | Aggregation |
| --- | --- | --- |
| `unique_ttl_values` | `IP_TTL` | `nunique` |
| `unique_destination_ports` | `DST_PORT` | `nunique` |

The artifact exposes the raw requirement as:

```python
classifier.required_columns == ("IP_TTL", "DST_PORT")
```

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
  model_path: ./detectors/nat_detector/final_models/basic_tree/nat_basic_tree.joblib
  threshold: 0.5
  feature_mapping:
    IP_TTL: IP_TTL
    DST_PORT: DST_PORT
```
