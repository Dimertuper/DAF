"""Tests of the SNI annotator."""

from helpers import ANNOTATORS, ROOT, daf_config, flows_of, ips, module

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
