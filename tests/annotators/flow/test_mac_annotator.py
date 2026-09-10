"""Tests of the MAC annotator."""

from helpers import ANNOTATORS, ROOT, daf_config, flows_of, ips, module

mac = module(ANNOTATORS / "flow" / "mac_annotator" / "mac_annotator.py")
DB = ROOT / "dbs" / "mac_annotator-vendor_os_db.csv"


def test_oui_database():
    database = mac.OUIDatabase(str(DB))

    assert database.annotation_for("00:05:02:11:22:33") == ["end-device", None, "macos"]
    assert database.annotation_for("FF:FF:FF:00:00:00") == [None, None, None]


def test_mac_annotator_uses_oui_and_flags_multiple_macs():
    config = daf_config(mac_annotator={"db_file": str(DB), "src_mac_field": "SRC_MAC"})
    annotator = mac.MACAnnotator(config)
    apple, shared = ips("10.0.0.1", "10.0.0.2")

    annotator.run(
        [apple, shared],
        {
            "10.0.0.1": flows_of("10.0.0.1", rows=2, SRC_MAC="00:05:02:11:22:33"),
            "10.0.0.2": flows_of("10.0.0.2", rows=2, SRC_MAC=["00:05:02:00:00:01", "00:10:FA:00:00:02"]),
        },
    )

    assert annotator.kind == "flow"
    assert apple.annotations["mac_annotator"].os_family == "macos"
    assert shared.multi_device[0][0] == "MAC"
    assert "mac_annotator" not in shared.annotations


def test_destination_macs_annotate_ips_without_source_flows():
    config = daf_config(
        mac_annotator={"db_file": str(DB), "src_mac_field": "SRC_MAC", "dst_mac_field": "DST_MAC"}
    )
    config["daf"]["dst_ip_field"] = "DST_IP"
    annotator = mac.MACAnnotator(config)
    destination = ips("10.0.0.9")[0]
    flows = flows_of("10.0.0.1", SRC_MAC="00:10:FA:00:00:01", DST_IP="10.0.0.9", DST_MAC="00:05:02:00:00:09")

    annotator.run([destination], {"10.0.0.1": flows})

    assert not annotator.requires_src_flows
    assert destination.annotations["mac_annotator"].os_family == "macos"
