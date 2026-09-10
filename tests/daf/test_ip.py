"""Tests of the IP state and the merging of annotations."""

import pytest

from annotation import Annotation
from ip import IP, MERGE_FAIL_LABEL, IPCollection, IPDataFile


def test_agreeing_annotators_set_final_annotation():
    ip = IP("10.0.0.1")
    ip.add_annotation("a", Annotation("end-device", None, "windows", "windows", None))
    ip.add_annotation("b", Annotation("end-device", None, "windows", None, None))

    ip.perform_annotation(min_annotators_count=2)

    assert ip.ret_annotation() == ["end-device", None, "windows", None, None]
    assert ip.multi_device == []


def conflicting_ip():
    ip = IP("10.0.0.1")
    for name, family in [("a", "windows"), ("b", "windows"), ("c", "linux"), ("d", "linux")]:
        ip.add_annotation(name, Annotation(None, None, family, None, None))
    return ip


def test_conflicting_annotators_flag_multi_device():
    ip = conflicting_ip()

    ip.perform_annotation(min_annotators_count=1)

    assert ip.final_annotation.os_family is None
    assert ip.multi_device[0][0] == MERGE_FAIL_LABEL


def test_one_outlier_is_recorded_as_one_miss():
    ip = IP("10.0.0.1")
    for name, family in [("a", "linux"), ("b", "linux"), ("c", "windows")]:
        ip.add_annotation(name, Annotation(None, None, family, None, None))

    ip.perform_annotation(min_annotators_count=2)

    assert ip.final_annotation.os_family is None
    assert len(ip.one_miss) == 1


def test_hand_annotation_overrides_final_annotation():
    ip = IP("10.0.0.1")
    ip.add_annotation("a", Annotation(None, None, "windows", None, None))
    ip.add_annotation("hand_annotator", Annotation(None, None, "linux", None, None))

    ip.perform_annotation(min_annotators_count=1)

    assert ip.final_annotation.os_family == "linux"
    assert ip.hand_miss


def test_perform_annotation_is_idempotent():
    ip = conflicting_ip()

    ip.perform_annotation(min_annotators_count=1)
    ip.perform_annotation(min_annotators_count=1)

    assert len(ip.multi_device) == 1


def test_export_and_load_round_trip():
    ip = IP("10.0.0.1")
    ip.add_annotation("a", Annotation("end-device", None, "linux", "debian", None))
    ip.add_data("a", {"value": 1})
    ip.multi_device.append(["MAC", ["aa", "bb"]])
    ip.window_results.append({"window_index": 0, "row_start": 0, "row_end": 9})
    ip.perform_annotation(min_annotators_count=1)

    loaded = IP.load(ip.export())

    assert loaded.export() == ip.export()


def test_invalid_taxonomy_is_not_set():
    annotation = Annotation("not-a-group", None, "not-an-os", None, None)

    assert annotation.is_empty()


def test_ip_collection_keeps_first_object():
    first = [IP("10.0.0.1"), IP("10.0.0.2")]
    collection = IPCollection(first, [IP("10.0.0.2"), IP("10.0.0.3")])

    assert [str(ip.ip_addr) for ip in collection] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert collection.to_list()[1] is first[1]
    assert "10.0.0.3" in collection and IP("10.0.0.1") in collection
    assert not collection.add(IP("10.0.0.1"))
    assert len(collection) == 3


def test_ip_data_file_round_trip(tmp_path):
    ip = IP("10.0.0.1")
    ip.add_annotation("a", Annotation(None, None, "linux", None, None))
    path = tmp_path / "ip_data.json"

    IPDataFile(path).save([ip])
    (loaded,) = IPDataFile(path).load()

    assert loaded.export() == ip.export()


def test_ip_data_file_missing(tmp_path):
    with pytest.raises(ValueError):
        IPDataFile(tmp_path / "missing.json").load()
