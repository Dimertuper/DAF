"""Tests of the Shodan annotator."""

from helpers import ANNOTATORS, daf_config, ips, module

shodan = module(ANNOTATORS / "ip" / "shodan_annotator" / "shodan_annotator.py")
CONFIG = {"shodan_api_key_file": "key.txt", "shodan_idb_url": "idb/", "shodan_api_url": "api/"}


def test_defaults_are_set():
    annotator = shodan.ShodanAnnotator(daf_config(shodan_annotator=dict(CONFIG)))

    assert annotator.config["max_timeouts"] == 5
    assert annotator.config["base_wait_time"] == 10


def test_shodan_annotator_stores_result(monkeypatch):
    monkeypatch.setattr(
        shodan.ShodanClient,
        "query",
        lambda self, ip: ("linux", [22], (None, None, "linux", None, None)),
    )
    ip = ips("10.0.0.1")[0]

    shodan.ShodanAnnotator(daf_config(shodan_annotator=dict(CONFIG))).run([ip])

    assert ip.data["shodan_annotation"] == ["linux", [22]]
    assert ip.annotations["shodan_annotation"].os_family == "linux"


def test_shodan_response_to_annotation():
    assert shodan.ShodanClient.to_annotation("Ubuntu 22.04", [443]) == (
        "server", "web", "linux", "ubuntu", "ubuntu 22.04"
    )
    assert shodan.ShodanClient.to_annotation("Windows 10", []) == (
        "end-device", "workstation", "windows", "windows", "windows 10"
    )
    assert shodan.ShodanClient.to_annotation(None, [53])[:2] == ("server", "dns")


def test_unavailable_data_skips_api(monkeypatch):
    client = shodan.ShodanClient({**CONFIG, "http_request_timeout": 1, "max_timeouts": 0, "base_wait_time": 0})
    monkeypatch.setattr(shodan.ShodanClient, "has_data", lambda self, ip: False)

    assert client.query("10.0.0.1") == (None, None, None)
