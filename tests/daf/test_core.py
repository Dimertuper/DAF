"""Tests of the module base classes in core.py."""

import pandas as pd
import pytest

from annotation import Annotation
from config import ConfigError, Requirement
from helpers import daf_config, flows_of, ips
from dataset import FlowDataset
from core import Detector, FlowAnnotator, IPAnnotator


class CountingIPAnnotator(IPAnnotator):
    """IP annotator recording its calls."""

    name = "counting_ip"
    REQUIREMENTS = (Requirement("value", str),)

    def setup(self):
        self.setups = getattr(self, "setups", 0) + 1
        self.seen = []

    def annotate_ip(self, ip):
        self.seen.append(str(ip.ip_addr))
        ip.add_annotation(self.name, Annotation(None, None, self.config["value"], None, None))


class ColumnFlowAnnotator(FlowAnnotator):
    """Flow annotator requiring one column."""

    name = "column_flow"

    def required_columns(self):
        return ("OS",)

    def annotate_ip(self, ip, flows):
        ip.add_annotation(self.name, Annotation(None, None, flows["OS"].iloc[0], None, None))


class ThresholdDetector(Detector):
    """Detector flagging IPs with more than ``limit`` flows."""

    name = "threshold_detector"
    evidence_label = "THRESHOLD"
    REQUIREMENTS = (Requirement("limit", int, default=1),)

    def detect(self, ip, flows):
        return {"detected": len(flows) > self.config["limit"], "flows": len(flows)}


def test_module_requires_its_configuration_section():
    with pytest.raises(ConfigError):
        CountingIPAnnotator(daf_config())


def test_module_requires_configured_keys():
    with pytest.raises(ConfigError, match="counting_ip.value"):
        CountingIPAnnotator(daf_config(counting_ip={}))


def test_ip_annotator_annotates_all_ips_and_sets_up_once():
    module = CountingIPAnnotator(daf_config(counting_ip={"value": "linux"}))
    addresses = ips("10.0.0.1", "10.0.0.2")

    module.run(addresses, {"10.0.0.1": flows_of("10.0.0.1")})
    module.run(addresses)

    assert module.kind == "ip"
    assert module.setups == 1
    assert module.seen == ["10.0.0.1", "10.0.0.2"] * 2
    assert addresses[1].annotations["counting_ip"].os_family == "linux"


def test_flow_annotator_skips_ips_without_flows():
    module = ColumnFlowAnnotator(daf_config(column_flow={}))
    addresses = ips("10.0.0.1", "10.0.0.2")

    module.run(addresses, {"10.0.0.1": flows_of("10.0.0.1", OS="windows")})

    assert module.kind == "flow"
    assert "column_flow" in addresses[0].annotations
    assert "column_flow" not in addresses[1].annotations


def test_flow_annotator_validates_columns():
    module = ColumnFlowAnnotator(daf_config(column_flow={}))

    with pytest.raises(KeyError, match="OS"):
        module.run(ips("10.0.0.1"), {"10.0.0.1": flows_of("10.0.0.1", OTHER=1)})


def test_detector_stores_result_and_flags_multi_device():
    module = ThresholdDetector(daf_config(threshold_detector={"limit": 1}))
    single, many = ips("10.0.0.1", "10.0.0.2")

    module.run(
        [single, many],
        {"10.0.0.1": flows_of("10.0.0.1"), "10.0.0.2": flows_of("10.0.0.2", rows=3)},
    )

    assert single.data["threshold_detector"] == {"detected": False, "flows": 1}
    assert single.multi_device == []
    assert many.multi_device == [["THRESHOLD", {"detected": True, "flows": 3}]]
    assert not many.annotations


def test_empty_flows_are_not_detected():
    module = ThresholdDetector(daf_config(threshold_detector={}))
    ip = ips("10.0.0.1")[0]

    module.run([ip], {"10.0.0.1": pd.DataFrame({"SRC_IP": []})})

    assert "threshold_detector" not in ip.data


def test_daf_requirements_are_checked():
    class NeedsPort(IPAnnotator):
        name = "needs_port"
        DAF_REQUIREMENTS = (Requirement("src_port_field", str), Requirement("extra", int, default=3))

        def annotate_ip(self, ip):
            pass

    config = daf_config(needs_port={})
    assert NeedsPort(config).daf_config["extra"] == 3
    del config["daf"]["src_port_field"]
    with pytest.raises(ConfigError, match="daf.src_port_field"):
        NeedsPort(config)


def test_flow_dataset_is_a_lazy_mapping():
    flows = pd.DataFrame({"SRC_IP": ["10.0.0.2", "10.0.0.1", "10.0.0.2"], "X": [1, 2, 3]})
    dataset = FlowDataset(flows, "SRC_IP")

    assert "10.0.0.1" in dataset and len(dataset) == 2
    assert dataset._groups is None
    assert dataset["10.0.0.2"]["X"].tolist() == [1, 3]
    assert list(dataset) == ["10.0.0.1", "10.0.0.2"]
    assert list(dataset.flows_by_ip({"10.0.0.1"})) == ["10.0.0.1"]
    assert FlowDataset.coerce(dataset, "SRC_IP") is dataset
    assert len(FlowDataset.coerce({"10.0.0.1": flows.iloc[[1]]}, "SRC_IP").flows) == 1
    assert len(FlowDataset.coerce({}, "SRC_IP")) == 0


def test_detector_without_detect_all_works_ip_by_ip():
    module = ThresholdDetector(daf_config(threshold_detector={"limit": 1}))
    many = ips("10.0.0.2")[0]

    module.run([many], FlowDataset(flows_of("10.0.0.2", rows=3), "SRC_IP"))

    assert module.detect_all([many], {}) is None
    assert many.data["threshold_detector"] == {"detected": True, "flows": 3}
