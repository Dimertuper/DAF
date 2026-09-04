# NAT Detector

The NAT detector classifies each source IP's flow group with a trained model.
It records every Boolean decision and probability in the IP object's
existing `data` field, while retaining positive `multi_device` evidence for
compatibility with existing DAF output.

## Configuration

- `model_path`: Path to a trusted `NATClassifier` artifact.
- `threshold`: Optional probability threshold. The default is `0.5`.
- `feature_mapping`: Optional mapping from the model's canonical raw fields to
  columns in the input dataset.

```yaml
nat_detector:
  enabled: true
  path: auto
  model_path: "./detectors/nat_detector/final_models/decision_tree/nat_decision_tree_depth_8.joblib"
  threshold: 0.5
  feature_mapping:
    SRC_IP: "SRC_IP"
    SRC_PORT: "SRC_PORT"
    DST_PORT: "DST_PORT"
    TCP_SYN_SIZE: "TCP_SYN_SIZE"
    TCP_WIN: "TCP_WIN"
    IP_TTL: "IP_TTL"
    BYTES: "BYTES"
    BYTES_REV: "BYTES_REV"
    PACKETS: "PACKETS"
    PACKETS_REV: "PACKETS_REV"
```

The classifier combines a probability estimator with the pandas aggregation
that converts one IP's raw flow rows into one feature row:

```python
from detectors.nat_detector import NATClassifier

classifier = NATClassifier(
    model=trained_model,
    aggregation={
        "unique_ports": ("SRC_PORT", "nunique"),
        "unique_ttls": ("IP_TTL", "nunique"),
    },
    positive_label=1,
    threshold=0.5,
)

import joblib

joblib.dump(classifier, "nat_classifier.joblib")
```

Only load trusted model files. Joblib uses pickle and may execute code during
deserialization.

The serialized object must be a `NATClassifier`, not a raw estimator, so its
aggregation cannot be omitted. `NATClassifier.required_columns` reports the
raw flow schema required by an artifact. The configured feature mapping checks
that the corresponding input columns are available before annotation starts.

`NATClassifier` extends the shared `detectors.common.ProbabilityClassifier`.
The shared base defines the aggregate-then-predict lifecycle, validates
probabilities, and applies the decision threshold. The classifier and detector
entry point are implemented together in `nat_detector.py`.

## Direct use

```python
from detectors.nat_detector import NATClassifier
import joblib

classifier = joblib.load("nat_classifier.joblib")
is_nat, probability = classifier.classify(ip_flows)
```

DAF discovers `nat_detector.py` and calls:

```python
annotate(ip_addresses, config, ip_data_dict) -> None
```

## Training data

`IPFlowDataset` and `TimeWindowedIPFlowDataset` from the shared
`detectors.common` module turns CSV or pandas inputs into training-data
abstractions. `IPFlowDataset` acts as the source-IP mapping and delegates custom
feature aggregation to the same classifier method used during execution:

```python
from detectors.common import IPFlowDataset
from detectors.nat_detector import NATClassifier

dataset = IPFlowDataset(flows)
classifier = NATClassifier(
    model,
    aggregation={
        "unique_ports": ("SRC_PORT", "nunique"),
        "unique_ttls": ("IP_TTL", "nunique"),
    },
)

training_features = dataset.apply(classifier.aggregate)

# DAF passes the same kind of one-IP DataFrame at execution time.
is_nat, probability = classifier.classify(dataset["10.0.0.1"])
```

The runnable [`train_ml_model.ipynb`](training/examples/train_ml_model.ipynb)
notebook demonstrates the general training contract with a small example.
Concrete reproducible notebooks, artifacts, feature mappings, and evaluation
results live together in their model packages:

- [`decision_tree`](final_models/decision_tree/README.md)
- [`basic_tree`](final_models/basic_tree/README.md)

Time-window training must use the same duration and timestamp policy as
`daf.windowing` during execution.
