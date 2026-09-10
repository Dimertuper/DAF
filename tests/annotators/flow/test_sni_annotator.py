"""Tests of the SNI annotator."""

import pandas as pd

from dataset import FlowDataset
from helpers import ANNOTATORS, ROOT, daf_config, flows_of, ips, module, per_ip_and_batch, random_flows

sni = module(ANNOTATORS / "flow" / "sni_annotator" / "sni_annotator.py")
DB = ROOT / "dbs" / "sni_annotator-os_database.csv"


def test_sni_database_requires_uri_paths():
    database = sni.SNIDatabase(str(DB))

    assert database.get_os(["vortex-win.data.microsoft.com", None])[0] == "windows"
    assert database.get_os(["msftconnecttest.com", None])[0] is None
    assert database.get_os(["msftconnecttest.com", "/connecttest.txt"])[0] == "windows"


def test_sni_annotator_creates_annotation_per_field():
    config = daf_config(sni_annotator={"db_file": str(DB), "fields": ["TLS_SNI", "MISSING_FIELD"]})
    annotator = sni.SNIAnnotator(config)
    ip = ips("10.0.0.1")[0]

    annotator.run([ip], {"10.0.0.1": flows_of("10.0.0.1", rows=2, TLS_SNI="vortex-win.data.microsoft.com")})

    assert annotator.fields == [["TLS_SNI", None]]
    assert ip.annotations["sni_annotator_TLS_SNI"].os_family == "windows"
    assert ip.data["sni_annotator_TLS_SNI"] == [["vortex-win.data.microsoft.com", None]]


def test_conflicting_server_names_flag_multi_device():
    database = sni.SNIDatabase(str(DB))
    names = [["vortex-win.data.microsoft.com", None], ["msftconnecttest.com", "/connecttest.txt"]]

    *_, multi_flag = sni.SNIAnnotator.annotation_from_server_names(names, database, 1)

    assert multi_flag == []


def test_batch_equals_per_ip():
    hosts = ["vortex-win.data.microsoft.com", "msftconnecttest.com", "example.org", None, ""]
    flows = random_flows({"TLS_SNI": hosts, "HTTP_HOST": hosts, "HTTP_URL": ["/connecttest.txt", "", None, "/x"]})
    config = daf_config(sni_annotator={"db_file": str(DB), "fields": ["TLS_SNI", ["HTTP_HOST", "HTTP_URL"]]})

    per_ip, batch = per_ip_and_batch(lambda: sni.SNIAnnotator(config), flows)

    assert per_ip == batch
    assert any("sni_annotator_TLS_SNI" in ip["annotations"] for ip in batch)


def test_missing_uri_from_csv(tmp_path):
    path = tmp_path / "flows.csv"
    path.write_text("SRC_IP,HTTP_HOST,HTTP_URL\n10.0.0.1,msftconnecttest.com,\n10.0.0.1,msftconnecttest.com,/connecttest.txt\n")
    flows = pd.read_csv(path)
    config = daf_config(sni_annotator={"db_file": str(DB), "fields": [["HTTP_HOST", "HTTP_URL"]]})
    ip = ips("10.0.0.1")[0]

    sni.SNIAnnotator(config).run([ip], FlowDataset(flows, "SRC_IP"))

    assert ip.annotations["sni_annotator_HTTP_HOST"].os_family == "windows"

