"""Tests of the output file naming and writing."""

import argparse
import csv

import pandas as pd

from annotation import Annotation
from helpers import daf_config, ips
from output import AnnotationListExporter, DatasetAnnotator, OutputPaths


def paths(dataset=None, reannotation=None):
    return OutputPaths(argparse.Namespace(dataset=dataset, reannotation=reannotation))


def test_output_paths():
    assert paths("data/flows.csv").annotation_list == "data/flows_ip_annotation_list.csv"
    assert paths("data/flows.csv").annotated_dataset == "data/flows_annotated.csv"
    assert paths("data/flows.csv").ip_data == "data/flows_ip_data.json"
    assert paths("new.csv", "old.json").annotation_list == "new_ip_annotation_list_reannotation.csv"
    assert paths(None, "old.json").annotation_list == "old_ip_annotation_list_reannotation.csv"
    assert paths("new.csv", "old.json").ip_data == "old_ip_data_updated.json"


def annotated_ips():
    first, second = ips("10.0.0.1", "10.0.0.2")
    first.add_annotation("mac_annotator", Annotation(None, None, "macos", None, None))
    first.perform_annotation(1)
    second.multi_device.append(["MAC", ["a", "b"]])
    return [first, second]


def test_annotation_list_with_module_columns(tmp_path):
    config = daf_config(
        mac_annotator={}, sni_annotator={"fields": ["TLS_SNI", ["HTTP_HOST", "HTTP_URL"]]},
        hand_annotator={"enabled": False},
    )
    path = tmp_path / "list.csv"

    AnnotationListExporter(config, ",").write(annotated_ips(), str(path))

    header, first, second = list(csv.reader(path.read_text().splitlines()))
    assert header[:2] == ["ip_address", "possible_NAT"]
    assert "mac_annotator_os_family" in header and "sni_annotator_HTTP_HOST_group" in header
    assert not any(column.startswith("hand_annotator") for column in header)
    assert first[header.index("final_annotation_os_family")] == "macos"
    assert second[1] == "True"


def test_annotation_list_final_only(tmp_path):
    config = daf_config(mac_annotator={})
    config["daf"]["export_full_annotation"] = False
    path = tmp_path / "list.csv"

    AnnotationListExporter(config, ";").write(annotated_ips(), str(path))

    assert len(path.read_text().splitlines()[0].split(";")) == 7


def test_dataset_annotator_in_memory_and_chunks(tmp_path):
    dataset = tmp_path / "flows.csv"
    pd.DataFrame({"SRC_IP": ["10.0.0.1", "10.0.0.2", "10.0.0.1"], "X": [1, 2, 3]}).to_csv(dataset, index=False)
    annotator = DatasetAnnotator(annotated_ips(), "SRC_IP")

    flows = annotator.write(pd.read_csv(dataset), str(tmp_path / "memory.csv"))
    stats = annotator.write_chunks(str(dataset), ",", str(tmp_path / "chunks.csv"), chunk_size=2)

    assert flows["os_family"].tolist()[0] == "macos"
    assert stats == (3, 2)
    pd.testing.assert_frame_equal(pd.read_csv(tmp_path / "memory.csv"), pd.read_csv(tmp_path / "chunks.csv"))
