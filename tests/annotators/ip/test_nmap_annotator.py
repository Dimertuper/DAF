"""Tests of the Nmap annotator in the passive and the active mode."""

import argparse
import os
import stat

import pytest

from config import ConfigError
from core import IPAnnotator
from helpers import ANNOTATORS, ROOT, daf_config, ips, module
from pipeline import DAFRunner, ModuleRunner

nmap = module(ANNOTATORS / "ip" / "nmap_annotator" / "nmap_annotator.py")

EXAMPLE_XML = ROOT / "examples" / "nmap" / "nmap_scan_example.xml"
RULES = ROOT / "dbs" / "nmap_annotator-rules.csv"
EXPECTED = {
    "192.0.2.10": ["server", "web", "linux", "ubuntu", "24.04"],
    "192.0.2.1": ["net-device", None, "linux", "cisco ios", "15.2"],
    "192.0.2.20": [None, None, "windows", "windows", None],
    "192.0.2.30": ["end-device", "printer", None, None, None],
}


def nmap_section(**options):
    section = {
        "xml_file": str(EXAMPLE_XML),
        "db_file": str(RULES),
        "min_os_accuracy": 95,
        "min_service_confidence": 7,
    }
    section.update(options)
    return section


def annotator(**options):
    return nmap.NmapAnnotator(daf_config(nmap_annotator=nmap_section(**options)))


@pytest.fixture
def fake_nmap(tmp_path):
    """Executable writing the example report to the -oX path and its targets to a file."""

    script = tmp_path / "fake_nmap"
    script.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in\n'
        f'    -iL) cp "$2" "{tmp_path}/targets.txt"; shift ;;\n'
        f'    -oX) cp "{EXAMPLE_XML}" "$2"; shift ;;\n'
        "  esac\n"
        "  shift\n"
        "done\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_parse_example_report():
    evidence = nmap.NmapReportParser.parse(str(EXAMPLE_XML))

    assert set(evidence) == set(EXPECTED) | {"192.0.2.40"}
    assert evidence["192.0.2.40"]["host"]["status"]["state"] == "down"
    assert evidence["192.0.2.10"]["host"]["ports"]


@pytest.mark.parametrize(
    "content, error",
    [("<nmaprun", ValueError), ('<other scanner="nmap"/>', ValueError)],
)
def test_invalid_reports_are_rejected(tmp_path, content, error):
    path = tmp_path / "report.xml"
    path.write_text(content)

    with pytest.raises(error):
        nmap.NmapReportParser.parse(str(path))
    with pytest.raises(FileNotFoundError):
        nmap.NmapReportParser.parse(str(tmp_path / "missing.xml"))


def test_rule_database_validation(tmp_path):
    assert set(nmap.NmapRuleSet(str(RULES)).rules) <= nmap.RULE_SOURCES

    header = "source,pattern,group,class,os_family,os_type,os_version\n"
    for row in ["unknown,x,,,,,", "service_name,(,,,,,", "service_name,x,server,no class,,,"]:
        path = tmp_path / "rules.csv"
        path.write_text(header + row + "\n")
        with pytest.raises(ValueError):
            nmap.NmapRuleSet(str(path))


@pytest.mark.parametrize(
    "options, key",
    [
        ({"min_os_accuracy": 101}, "min_os_accuracy"),
        ({"min_service_confidence": -1}, "min_service_confidence"),
        ({"mode": "x"}, "mode"),
        ({"xml_file": None}, "xml_file"),
        ({"dry_run": "yes"}, "dry_run"),
    ],
)
def test_invalid_configuration(options, key):
    with pytest.raises(ConfigError, match=f"nmap_annotator.{key}"):
        annotator(**options)


def test_active_mode_does_not_need_a_report():
    module_ = annotator(mode="active", xml_file=None, arguments=["-sT"], targets=["192.0.2.0/30"])

    assert module_.targets.addresses == ["192.0.2.1", "192.0.2.2"]
    assert module_.config["scan_dataset_ips"] is True


def test_passive_mode_provides_and_annotates_report_ips():
    module = annotator()
    source, provided = module.provide_ips()

    module.run(provided)

    assert source == str(EXAMPLE_XML.resolve())
    assert isinstance(module, IPAnnotator) and not module.deferred
    annotations = {
        str(ip.ip_addr): ip.annotations["nmap_annotator"].ret_annotation()
        for ip in provided
        if "nmap_annotator" in ip.annotations
    }
    assert annotations == EXPECTED
    assert all("nmap_annotator" in ip.data for ip in provided)


def test_dataset_ips_missing_in_report_are_skipped():
    ip = ips("10.0.0.1")[0]

    annotator().run([ip])

    assert not ip.annotations and not ip.data


def test_runner_without_dataset(tmp_path):
    xml = tmp_path / "scan.xml"
    xml.write_bytes(EXAMPLE_XML.read_bytes())
    config = daf_config(nmap_annotator=nmap_section(xml_file=str(xml)))
    arg = argparse.Namespace(dataset=None, reannotation=None, d=",", logfile=False)

    DAFRunner(arg, config, [nmap.NmapAnnotator(config)]).run()

    assert (tmp_path / "scan_ip_annotation_list.csv").is_file()
    assert (tmp_path / "scan_ip_data.json").is_file()


def test_expand_targets():
    assert nmap.NmapTargets.expand(["192.0.2.1", "192.0.2.0/30"]) == ["192.0.2.1", "192.0.2.1", "192.0.2.2"]
    with pytest.raises(ValueError):
        nmap.NmapTargets.expand(["not-an-ip"])
    with pytest.raises(ValueError):
        nmap.NmapTargets.expand(["10.0.0.0/8"])


def test_scanner_command_and_reserved_options():
    scanner = nmap.NmapScanner("nmap", ["-sT", "-n"], privileged=True)

    assert scanner.command("t.txt", "o.xml") == [
        "nmap", "-sT", "-n", "--privileged", "-iL", "t.txt", "-oX", "o.xml"
    ]
    assert nmap.NmapScanner().arguments == nmap.DEFAULT_ARGUMENTS
    with pytest.raises(ValueError):
        nmap.NmapScanner(arguments=["-oX", "x.xml"])
    with pytest.raises(ValueError):
        nmap.NmapScanner(timeout=0)


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX only")
def test_privileged_options_require_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    with pytest.raises(PermissionError, match="-sS"):
        nmap.NmapScanner(arguments=["-sS"]).check_privileges()
    nmap.NmapScanner(arguments=["-sS"], privileged=True).check_privileges()
    nmap.NmapScanner(arguments=["-sT"]).check_privileges()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    nmap.NmapScanner(arguments=["-sS", "-O"]).check_privileges()


def test_dry_run_does_not_start_nmap(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Nmap must not run")

    monkeypatch.setattr(nmap.subprocess, "run", fail)
    scanner = nmap.NmapScanner("missing-nmap-binary", ["-sT"], dry_run=True)

    assert scanner.scan(["192.0.2.1"], str(tmp_path / "out.xml")) is False


def test_missing_nmap_executable(tmp_path):
    with pytest.raises(FileNotFoundError):
        nmap.NmapScanner("missing-nmap-binary", ["-sT"]).scan(["192.0.2.1"], str(tmp_path / "o.xml"))


def test_active_mode_scans_annotated_ips_except_multi_devices(tmp_path, fake_nmap):
    output = tmp_path / "active.xml"
    module = annotator(
        mode="active",
        nmap_path=str(fake_nmap),
        arguments=["-sT"],
        targets=["192.0.2.20"],
        output_xml=str(output),
    )
    _, provided = module.provide_ips()
    dataset_ips = ips("192.0.2.10", "192.0.2.30")
    dataset_ips[1].multi_device.append(["NAT_detector", {"detected": True}])

    module.run(dataset_ips + provided)

    assert module.deferred
    assert [str(ip.ip_addr) for ip in provided] == ["192.0.2.20"]
    assert (tmp_path / "targets.txt").read_text().split() == ["192.0.2.10", "192.0.2.20"]
    assert output.is_file()
    assert dataset_ips[0].annotations["nmap_annotator"].ret_annotation() == EXPECTED["192.0.2.10"]
    assert provided[0].annotations["nmap_annotator"].os_family == "windows"


def test_active_mode_can_scan_only_configured_targets(tmp_path, fake_nmap):
    module = annotator(
        mode="active",
        nmap_path=str(fake_nmap),
        arguments=["-sT"],
        targets=["192.0.2.1"],
        scan_dataset_ips=False,
        output_xml=str(tmp_path / "active.xml"),
    )
    _, provided = module.provide_ips()

    module.run(ips("192.0.2.10") + provided)

    assert (tmp_path / "targets.txt").read_text().split() == ["192.0.2.1"]


def test_failed_nmap_run_is_reported(tmp_path):
    script = tmp_path / "failing_nmap"
    script.write_text("#!/bin/sh\necho 'scan failed' >&2\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    with pytest.raises(RuntimeError, match="scan failed"):
        nmap.NmapScanner(str(script), ["-sT"]).scan(["192.0.2.1"], str(tmp_path / "o.xml"))


class OrderAnnotator(IPAnnotator):
    """IP annotator recording the order of the runs."""

    name = "order_annotator"
    order = []

    def __init__(self, config, deferred):
        super().__init__(config)
        self._deferred = deferred

    @property
    def deferred(self):
        return self._deferred

    def annotate_ip(self, ip):
        self.order.append(self._deferred)


@pytest.mark.parametrize("threads", [False, True])
def test_deferred_modules_run_last(threads):
    config = daf_config(order_annotator={})
    OrderAnnotator.order = []
    modules = [OrderAnnotator(config, True), OrderAnnotator(config, False)]

    ModuleRunner(modules, threads).run(ips("10.0.0.1"), {})

    assert OrderAnnotator.order == [False, True]
