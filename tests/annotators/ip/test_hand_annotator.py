"""Tests of the hand annotator."""

import pytest

from config import ConfigError
from helpers import ANNOTATORS, daf_config, ips, module

hand = module(ANNOTATORS / "ip" / "hand_annotator" / "hand_annotator.py")


@pytest.fixture
def hand_db(tmp_path):
    path = tmp_path / "hand.csv"
    path.write_text(
        "ip_address,group,class,os-family,os-type,os-version\n"
        "10.0.0.1,end-device,workstation,windows,windows,\n"
        "10.0.1.{1-3},end-device,mobile,android,,\n"
        "192.168.0.0/30,end-device,printer,linux,,\n"
    )
    return path


def test_rules_match_addresses_ranges_and_networks(hand_db):
    rules = hand.HandAnnotationRules(hand_db)
    single, in_range, in_network, other = ips("10.0.0.1", "10.0.1.2", "192.168.0.2", "10.0.0.2")

    assert rules.lookup(single.ip_addr)[1] == "workstation"
    assert rules.lookup(in_range.ip_addr)[1] == "mobile"
    assert rules.lookup(in_network.ip_addr)[1] == "printer"
    assert rules.lookup(other.ip_addr) is None


def test_hand_annotator(hand_db):
    annotator = hand.HandAnnotator(daf_config(hand_annotator={"db": str(hand_db)}))
    single, other = ips("10.0.0.1", "10.0.0.2")

    annotator.run([single, other])

    assert annotator.kind == "ip"
    assert single.annotations["hand_annotator"].ret_annotation() == [
        "end-device", "workstation", "windows", "windows", None
    ]
    assert "hand_annotator" not in other.annotations


def test_missing_database_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="hand_annotator.db"):
        hand.HandAnnotator(daf_config(hand_annotator={"db": str(tmp_path / "missing.csv")}))
