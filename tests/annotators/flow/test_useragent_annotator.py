"""Tests of the useragent annotator."""

from types import SimpleNamespace

import pytest

from config import ConfigError
from helpers import ANNOTATORS, daf_config, flows_of, module

useragent = module(ANNOTATORS / "flow" / "useragent_annotator" / "useragent_annotator.py")
Classifier = useragent.UserAgentClassifier


@pytest.mark.parametrize(
    "os, expected",
    [
        ("Windows 10", ["windows", "windows", "10"]),
        ("android 13", ["android", "android", "13"]),
        ("mac os x 10.15", ["macos", "macos", "10.15"]),
        ("Ubuntu", ["ubuntu", None, None]),
        ("Linux Mint 21", ["linux", "mint", "21"]),
    ],
)
def test_separate_os_info(os, expected):
    assert Classifier.separate_os_info(os) == expected


def agent(os, mine_os="", tags=None):
    return SimpleNamespace(os=os, mine_os=mine_os, tags=tags or {})


def test_annotation_from_useragents():
    tags = {"operating_system": "Windows 10", "hardware_type": "computer"}
    agents = {"a": agent("Windows 10", tags=tags), "b": agent("Windows 10", tags=dict(tags))}

    assert Classifier.annotation_from_useragents(agents, 2) == [
        "end_device", "workstation", "windows", "windows", "10", []
    ]


def test_too_few_useragents_give_no_os():
    agents = {"a": agent("Windows 10")}

    assert Classifier.annotation_from_useragents(agents, 2)[:5] == [None] * 5


def test_conflicting_useragents_flag_multi_device():
    agents = {"a": agent("Windows 10"), "b": agent("Android 13")}

    *_, multi_flag = Classifier.annotation_from_useragents(agents, 3)

    assert sorted(multi_flag[0]) == ["Android 13", "Windows 10"]


def test_collect_useragents():
    flows = flows_of("10.0.0.1", rows=2, UA=["Mozilla/5.0", None])

    assert Classifier.collect_useragents(flows, {"field": "UA"}) == ["Mozilla/5.0"]
    assert Classifier.collect_useragents(None, {"field": "UA"}) is None


def test_missing_databases_are_config_errors(tmp_path):
    config = daf_config(
        useragent_annotator={
            "keywords_db": str(tmp_path / "k.csv"),
            "browsers_db": str(tmp_path / "b.csv"),
            "others_db": str(tmp_path / "o.csv"),
            "full_search": True,
            "mine_flag": True,
            "field": "UA",
        }
    )

    with pytest.raises(ConfigError, match="useragent_annotator.keywords_db"):
        useragent.UserAgentAnnotator(config)
