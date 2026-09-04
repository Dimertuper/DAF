#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: nat_detector.py
Description: Detect NAT devices with a trained machine-learning model.
"""

import logging
from pathlib import Path
from typing import Any

import pandas as pd

from detectors.common import ProbabilityClassifier

logger = logging.getLogger("NAT Detector")


class NATClassifier(ProbabilityClassifier[pd.DataFrame, pd.Series]):
    """Aggregate and classify all source-flow rows belonging to one IP."""

    def __init__(
        self,
        model: Any,
        aggregation: dict[str, tuple[str, str]],
        *,
        positive_label: Any = 1,
        threshold: float = 0.5,
    ) -> None:
        self.model = model
        self.aggregation = aggregation
        self.positive_label = positive_label
        super().__init__(threshold)

    @property
    def feature_names(self) -> tuple[str, ...]:
        """Return model feature names in their aggregation order."""

        return tuple(self.aggregation)

    @property
    def required_columns(self) -> tuple[str, ...]:
        """Return the raw flow columns required by the aggregation."""

        return tuple(dict.fromkeys(column for column, _ in self.aggregation.values()))

    def aggregate(self, flows: pd.DataFrame) -> pd.Series:
        """Aggregate one IP's flows into one model feature row."""

        features = flows.groupby(lambda _: 0).agg(**self.aggregation).iloc[0]
        features.name = None
        return features

    def predict_probability(self, features: pd.Series) -> float:
        """Predict the positive-class probability for one feature row."""

        probabilities = self.model.predict_proba(features.to_frame().T)[0]
        positive_index = list(self.model.classes_).index(self.positive_label)
        return float(probabilities[positive_index])


def _load_classifier(config: dict) -> NATClassifier:
    """Create the configured NAT classifier."""

    if "nat_detector" not in config or "model_path" not in config["nat_detector"]:
        logger.error("NAT detector model_path not found in configuration file")
        raise RuntimeError("NAT Detector:: Configuration or model_path not found")

    try:
        import joblib
    except ImportError as error:
        raise RuntimeError(
            "Loading a NAT classifier requires the nat_detector dependencies"
        ) from error

    detector_config = config["nat_detector"]
    model_path = Path(detector_config["model_path"]).expanduser()
    classifier = joblib.load(model_path)
    classifier_type = type(classifier)
    if (
        classifier_type.__module__ != NATClassifier.__module__
        or classifier_type.__qualname__ != NATClassifier.__qualname__
    ):
        raise TypeError("NAT model file must contain a NATClassifier")

    if "threshold" in detector_config:
        classifier.threshold = detector_config["threshold"]
    return classifier


def _load_feature_mapping(classifier: NATClassifier, config: dict) -> dict[str, str]:
    """Map the model's canonical raw fields to input dataset columns."""

    configured_mapping = config["nat_detector"].get("feature_mapping", {})
    if not isinstance(configured_mapping, dict):
        raise TypeError("NAT detector feature_mapping must be a mapping")

    unknown_fields = set(configured_mapping).difference(classifier.required_columns)
    if unknown_fields:
        unknown = ", ".join(sorted(unknown_fields))
        raise ValueError(f"NAT detector feature_mapping contains unknown fields: {unknown}")

    invalid_fields = [
        field
        for field, column in configured_mapping.items()
        if not isinstance(column, str) or not column
    ]
    if invalid_fields:
        invalid = ", ".join(sorted(invalid_fields))
        raise ValueError(f"NAT detector feature_mapping requires column names for: {invalid}")

    return {field: configured_mapping.get(field, field) for field in classifier.required_columns}


def _map_flow_columns(flows: pd.DataFrame, feature_mapping: dict[str, str]) -> pd.DataFrame:
    """Expose configured dataset columns under their canonical model names."""

    missing_columns = [column for column in feature_mapping.values() if column not in flows.columns]
    if missing_columns:
        missing = ", ".join(dict.fromkeys(missing_columns))
        raise KeyError(f"NAT detector input is missing mapped columns: {missing}")

    if all(field == column for field, column in feature_mapping.items()):
        return flows

    mapped_flows = flows.copy()
    for field, column in feature_mapping.items():
        mapped_flows[field] = flows[column]
    return mapped_flows


def annotate(ip_addresses: list, config: dict, ip_data_dict: dict) -> None:
    """Classify each IP flow group and flag probable NAT devices.

    Parameters
    ----------
    ip_addresses : list
        IP address objects prepared by DAF.
    config : dict
        DAF configuration.
    ip_data_dict : dict
        Flow DataFrames keyed by source IP address.
    """

    classifier = _load_classifier(config)
    feature_mapping = _load_feature_mapping(classifier, config)
    first_flow_table = next(
        (
            flows
            for flows in ip_data_dict.values()
            if isinstance(flows, pd.DataFrame) and not flows.empty
        ),
        None,
    )
    if first_flow_table is not None:
        _map_flow_columns(first_flow_table, feature_mapping)

    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    for index, ip_address in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (index % log_interval == 0 or index == total_ips):
            progress = index / total_ips * 100
            logger.info(f"    -- NAT detection ... {progress:.0f} %")

        ip_flows = ip_data_dict.get(str(ip_address.ip_addr))
        if ip_flows is None:
            continue
        if not isinstance(ip_flows, pd.DataFrame):
            raise TypeError("NAT Detector:: IP flow data must be a pandas DataFrame")
        if ip_flows.empty:
            continue

        mapped_ip_flows = _map_flow_columns(ip_flows, feature_mapping)
        is_nat, probability = classifier.classify(mapped_ip_flows)
        detection = {
            "detected": is_nat,
            "probability": probability,
            "threshold": classifier.threshold,
            "model": type(classifier.model).__name__,
        }
        ip_address.add_data("nat_detector", detection)
        if is_nat:
            ip_address.multi_device.append(["NAT_detector", detection])

    logger.info("    -- NAT detection ... DONE")


__all__ = ["NATClassifier", "annotate"]
