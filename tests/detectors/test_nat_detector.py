"""Tests of the NAT detector."""

import pandas as pd
import pytest

from config import ConfigError
from helpers import DETECTORS, daf_config, flows_of, ips, module, per_ip_and_batch, random_flows

nat = module(DETECTORS / "nat_detector" / "nat_detector.py")


def test_heuristic_detection():
    detector = nat.NATDetector(
        daf_config(nat_detector={"field": "TTL", "min_unique_ttl": 2, "min_unique_src_ports": 3})
    )
    single, natted = ips("10.0.0.1", "10.0.0.2")

    detector.run(
        [single, natted],
        {
            "10.0.0.1": flows_of("10.0.0.1", rows=3, TTL=64, SRC_PORT=[1, 2, 3]),
            # TTL counts 1 and 2 -> two distinct counts, three source ports
            "10.0.0.2": flows_of("10.0.0.2", rows=3, TTL=[64, 128, 128], SRC_PORT=[1, 2, 3]),
        },
    )

    assert single.data["nat_detector"]["detected"] is False
    assert natted.data["nat_detector"]["detected"] is True
    assert natted.multi_device[0][0] == "NAT_detector"


def test_default_thresholds_and_requirements():
    detector = nat.NATDetector(daf_config(nat_detector={"field": "TTL"}))
    assert (detector.config["min_unique_ttl"], detector.config["min_unique_src_ports"]) == (5, 500)

    with pytest.raises(ConfigError, match="nat_detector.field"):
        nat.NATDetector(daf_config(nat_detector={}))


def test_missing_columns_are_reported():
    detector = nat.NATDetector(daf_config(nat_detector={"field": "TTL"}))

    with pytest.raises(KeyError, match="TTL"):
        detector.run(ips("10.0.0.1"), {"10.0.0.1": pd.DataFrame({"SRC_IP": ["10.0.0.1"], "SRC_PORT": [1]})})


def test_heuristic_batch_equals_per_ip():
    flows = random_flows({"TTL": [0, 64, 128, 255, None], "SRC_PORT": list(range(0, 40))}, rows=2000)
    config = daf_config(nat_detector={"field": "TTL", "min_unique_ttl": 3, "min_unique_src_ports": 25})

    per_ip, batch = per_ip_and_batch(lambda: nat.NATDetector(config), flows)

    assert per_ip == batch
    assert {ip["data"]["nat_detector"]["detected"] for ip in batch} == {True, False}
