"""Tests of the hostname annotator."""

from helpers import ROOT, ANNOTATORS, daf_config, ips, module

hostname = module(ANNOTATORS / "ip" / "hostname_annotator" / "hostname_annotator.py")
EXAMPLES = ROOT / "examples" / "basic"
DATABASES = (
    EXAMPLES / "hostname_annotator_full_match_example.csv",
    EXAMPLES / "hostname_annotator_sequences_example.csv",
    EXAMPLES / "hostname_annotator_subsequences_example.csv",
)


def test_rules():
    rules = hostname.HostnameRules(*DATABASES)

    assert rules.annotation_for("nerd.liberouter.org").os_type == "debian"
    assert rules.annotation_for("air1702.example.org")._class == "wifi router"
    assert rules.annotation_for("lab-ap.example.org").group == "net-device"
    # "office" is a sequence of another group, conflicting subsequences give nothing
    assert rules.annotation_for("office-ap.example.org") is None
    assert rules.annotation_for("unknown.example.org") is None


def test_hostname_annotator(monkeypatch):
    names = {"10.0.0.1": "nerd.liberouter.org"}
    monkeypatch.setattr(hostname.ReverseDNS, "resolve", lambda self, ip: names.get(ip))
    config = daf_config(
        hostname_annotator={
            "full_db": str(DATABASES[0]),
            "sequences_db": str(DATABASES[1]),
            "subsequences_db": str(DATABASES[2]),
            "timeout": 0,
        }
    )
    known, unknown = ips("10.0.0.1", "10.0.0.2")

    hostname.HostnameAnnotator(config).run([known, unknown])

    assert known.data["hostname_annotator"] == "nerd.liberouter.org"
    assert known.annotations["hostname_annotator"].os_type == "debian"
    assert not unknown.annotations and not unknown.data


def test_reverse_dns_of_localhost():
    assert hostname.ReverseDNS(0).resolve("127.0.0.1")
