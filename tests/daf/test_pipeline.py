"""Tests of the annotation pipeline."""

import argparse
import json

import pandas as pd
import pytest

from annotation import Annotation
from config import ConfigError
from core import Detector, FlowAnnotator, IPAnnotator
from dataset import FlowDataset
from helpers import daf_config, ips
from daf import DAFApplication
from pipeline import DAFRunner, ModuleRunner, WindowedDAFRunner

START = pd.Timestamp("2026-01-01T10:00:00Z")


class OnceIPAnnotator(IPAnnotator):
    """IP annotator counting how many times each IP was annotated."""

    name = "once_annotator"

    def setup(self):
        self.calls = {}

    def annotate_ip(self, ip):
        self.calls[str(ip.ip_addr)] = self.calls.get(str(ip.ip_addr), 0) + 1
        ip.add_annotation(self.name, Annotation("end-device", None, None, None, None))


class OSFlowAnnotator(FlowAnnotator):
    """Flow annotator reading the OS column."""

    name = "os_annotator"

    def setup(self):
        self.seen = []

    def required_columns(self):
        return ("OS",)

    def annotate_ip(self, ip, flows):
        self.seen.append(str(ip.ip_addr))
        ip.add_annotation(self.name, Annotation(None, None, flows["OS"].iloc[0], None, None))


class NATFlagDetector(Detector):
    """Detector flagging IPs whose flows have the NAT column set."""

    name = "flag_detector"

    def detect(self, ip, flows):
        return {"detected": bool(flows["NAT"].any())}


class FailingAnnotator(IPAnnotator):
    """IP annotator that always fails."""

    name = "failing_annotator"

    def annotate_ip(self, ip):
        raise ValueError("broken")


def write_flows(path, rows):
    """Write flows given as (minute, ip, os, nat) tuples."""

    pd.DataFrame(
        [
            {
                "TIME_FIRST": (START + pd.Timedelta(minutes=minute)).isoformat(),
                "SRC_IP": ip,
                "SRC_PORT": 1000,
                "DST_PORT": 443,
                "OS": os_family,
                "NAT": nat,
            }
            for minute, ip, os_family, nat in rows
        ]
    ).to_csv(path, index=False)


def create_runner(arg, config, modules):
    """Create the runner the application selects for a configuration."""

    return DAFApplication(arg, config, modules).create_runner()


def arguments(dataset, reannotation=None):
    return argparse.Namespace(dataset=str(dataset), reannotation=reannotation, d=",", logfile=False)


def modules_for(config):
    return [OnceIPAnnotator(config), OSFlowAnnotator(config), NATFlagDetector(config)]


def module_config(**daf):
    config = daf_config(once_annotator={}, os_annotator={}, flag_detector={})
    config["daf"].update(daf)
    return config


def test_flow_dataset_groups_by_ip_strings():
    flows = pd.DataFrame({"SRC_IP": ["10.0.0.1", "10.0.0.2", "10.0.0.1"]})

    grouped = FlowDataset(flows, "SRC_IP").flows_by_ip(keys={"10.0.0.1"})

    assert list(grouped) == ["10.0.0.1"]
    assert len(grouped["10.0.0.1"]) == 2


@pytest.mark.parametrize("threads", [False, True])
def test_module_runner_reports_failures(threads):
    config = daf_config(failing_annotator={})

    with pytest.raises(RuntimeError, match="modules failed"):
        ModuleRunner([FailingAnnotator(config)], threads).run(ips("10.0.0.1"), {})


def test_module_runner_runs_modules_of_one_kind():
    config = module_config()
    modules = modules_for(config)
    runner = ModuleRunner(modules, threads=False)
    addresses = ips("10.0.0.1")
    runner.run(addresses, {}, kind="ip")

    assert set(addresses[0].annotations) == {"once_annotator"}


def test_process_dataset_writes_outputs(tmp_path):
    dataset = tmp_path / "flows.csv"
    write_flows(dataset, [(0, "10.0.0.1", "linux", False), (1, "10.0.0.2", "windows", False)])
    config = module_config()

    create_runner(arguments(dataset), config, modules_for(config)).run()

    annotated = pd.read_csv(tmp_path / "flows_annotated.csv")
    assert annotated["os_family"].tolist() == ["linux", "windows"]
    assert annotated["group"].tolist() == ["end-device", "end-device"]
    exported = json.loads((tmp_path / "flows_ip_data.json").read_text())
    assert {ip["ip_addr"] for ip in exported} == {"10.0.0.1", "10.0.0.2"}
    assert (tmp_path / "flows_ip_annotation_list.csv").is_file()


def test_reannotation_annotates_only_unseen_ips(tmp_path):
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    write_flows(first, [(0, "10.0.0.1", "linux", False)])
    write_flows(second, [(0, "10.0.0.1", "linux", False), (1, "10.0.0.2", "windows", False)])
    config = module_config()
    DAFRunner(arguments(first), config, modules_for(config)).run()

    modules = modules_for(config)
    DAFRunner(arguments(second, str(tmp_path / "first_ip_data.json")), config, modules).run()

    assert modules[0].calls == {"10.0.0.2": 1}
    annotation_list = pd.read_csv(tmp_path / "second_ip_annotation_list_reannotation.csv")
    assert set(annotation_list["ip_address"]) == {"10.0.0.1", "10.0.0.2"}


def windowing(**options):
    return {"enabled": True, "type": "time", "size": "15min", "timestamp_field": "TIME_FIRST", **options}


def test_runner_requirements_are_checked(tmp_path):
    config = module_config()
    del config["daf"]["threads"]

    with pytest.raises(ConfigError, match="daf.threads"):
        DAFRunner(arguments(tmp_path / "flows.csv"), config, [])
    assert type(create_runner(arguments(tmp_path / "f.csv"), module_config(), [])) is DAFRunner


def test_windowed_runner_skips_multi_device_and_runs_ip_modules_once(tmp_path):
    dataset = tmp_path / "flows.csv"
    write_flows(
        dataset,
        [
            (0, "10.0.0.1", "linux", False),
            (1, "10.0.0.2", "windows", True),
            (16, "10.0.0.1", "linux", False),
            (17, "10.0.0.2", "windows", False),
            (31, "10.0.0.1", "windows", False),
            (32, "10.0.0.2", "windows", False),
        ],
    )
    config = module_config(windowing=windowing())
    modules = modules_for(config)
    runner = create_runner(arguments(dataset), config, modules)
    assert isinstance(runner, WindowedDAFRunner)

    runner.run()

    once, flow, _ = modules
    assert once.calls == {"10.0.0.1": 1, "10.0.0.2": 1}
    assert flow.seen.count("10.0.0.1") == 3
    assert flow.seen.count("10.0.0.2") == 1
    exported = {ip["ip_addr"]: ip for ip in json.loads((tmp_path / "flows_ip_data.json").read_text())}
    assert exported["10.0.0.2"]["data"]["window_voting"]["multi_device_window"] == 0
    assert len(exported["10.0.0.2"]["window_results"]) == 1
    assert exported["10.0.0.1"]["annotations"]["os_annotator"]["os_family"] == "linux"


def test_windowed_threshold_voting(tmp_path):
    dataset = tmp_path / "flows.csv"
    rows = [(15 * index, "10.0.0.1", family, False) for index, family in enumerate(["linux", "linux", "windows"])]
    write_flows(dataset, rows)

    for threshold, expected in [(0.6, "linux"), (0.7, None)]:
        config = module_config(windowing=windowing(consensus="threshold", threshold=threshold))
        create_runner(arguments(dataset), config, modules_for(config)).run()
        (ip,) = json.loads((tmp_path / "flows_ip_data.json").read_text())
        assert ip["annotations"]["os_annotator"]["os_family"] == expected


def test_windowed_reannotation_matches_full_run(tmp_path):
    rows = [(minute, f"10.0.0.{minute % 3 + 1}", "linux", False) for minute in range(0, 60, 4)]
    write_flows(tmp_path / "half.csv", rows[: len(rows) // 2])
    write_flows(tmp_path / "full.csv", rows)
    write_flows(tmp_path / "direct.csv", rows)
    config = module_config(windowing=windowing())

    create_runner(arguments(tmp_path / "half.csv"), config, modules_for(config)).run()
    create_runner(
        arguments(tmp_path / "full.csv", str(tmp_path / "half_ip_data.json")), config, modules_for(config)
    ).run()
    create_runner(arguments(tmp_path / "direct.csv"), config, modules_for(config)).run()

    reannotated = pd.read_csv(tmp_path / "full_ip_annotation_list_reannotation.csv")
    direct = pd.read_csv(tmp_path / "direct_ip_annotation_list.csv")
    pd.testing.assert_frame_equal(
        reannotated.sort_values("ip_address").reset_index(drop=True),
        direct.sort_values("ip_address").reset_index(drop=True),
    )


def test_ip_both_source_and_destination_is_annotated_once(tmp_path):
    dataset = tmp_path / "flows.csv"
    write_flows(dataset, [(0, "10.0.0.1", "linux", False), (1, "10.0.0.2", "windows", False)])
    flows = pd.read_csv(dataset)
    flows["DST_IP"] = ["10.0.0.2", "10.0.0.1"]
    flows.to_csv(dataset, index=False)
    config = module_config(dst_ip_field="DST_IP")
    modules = modules_for(config)

    create_runner(arguments(dataset), config, modules).run()

    assert modules[0].calls == {"10.0.0.1": 1, "10.0.0.2": 1}
    annotation_list = pd.read_csv(tmp_path / "flows_ip_annotation_list.csv")
    assert annotation_list["ip_address"].tolist() == ["10.0.0.1", "10.0.0.2"]
    assert pd.read_csv(tmp_path / "flows_annotated.csv")["os_family"].tolist() == ["linux", "windows"]

