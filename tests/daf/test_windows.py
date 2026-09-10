"""Tests of window iteration and window voting."""

import pandas as pd
import pytest

from annotation import Annotation
from config import ConfigError
from helpers import daf_config
from windows import (
    RowWindowIterator,
    TimeWindowIterator,
    WindowConfig,
    WindowMetadata,
    WindowObservation,
    WindowResolver,
    WindowResult,
    WindowVoting,
)

START = pd.Timestamp("2026-01-01T10:00:00Z")


def time_window(index, minutes=15):
    start = START + pd.Timedelta(minutes=minutes * index)
    return WindowMetadata(index=index, start=start, end=start + pd.Timedelta(minutes=minutes))


def observation(ip, os_family=None, multi_device=None, name="sni"):
    return WindowObservation(
        ip, {name: Annotation(None, None, os_family, None, None)}, multi_device or []
    )


@pytest.mark.parametrize(
    "method, threshold, expected",
    [("majority", 0.5, None), ("threshold", 0.3, "a"), ("threshold", 0.5, "a"), ("threshold", 0.6, None)],
)
def test_voting_rules(method, threshold, expected):
    # "a" has 2 of 4 non-empty votes
    assert WindowVoting(method, threshold).vote(["a", "a", "b", None, "c"]) == expected


def test_voting_majority_and_ties():
    assert WindowVoting().vote(["a", "a", "b"]) == "a"
    assert WindowVoting("threshold", 0.1).vote(["a", "b"]) is None
    assert WindowVoting().vote([None, ""]) is None


@pytest.mark.parametrize("method, threshold", [("unanimous", 0.5), ("threshold", 0), ("threshold", 1.5)])
def test_invalid_voting_is_rejected(method, threshold):
    with pytest.raises(ValueError):
        WindowVoting(method, threshold)


def test_vote_annotation_is_hierarchical():
    annotations = [
        Annotation(None, None, "linux", "debian", None),
        Annotation(None, None, "linux", "ubuntu", None),
        Annotation(None, None, "linux", "debian", None),
        Annotation(None, None, "windows", "windows", None),
    ]

    voted = WindowVoting().vote_annotation(annotations)

    assert voted.ret_annotation() == [None, None, "linux", "debian", None]


def test_parse_duration():
    assert TimeWindowIterator.parse_duration("15min") == pd.Timedelta(minutes=15)
    assert TimeWindowIterator.parse_duration(60) == pd.Timedelta(minutes=1)
    with pytest.raises(ValueError):
        TimeWindowIterator.parse_duration("0s")


def test_window_metadata_validation():
    with pytest.raises(ValueError):
        WindowMetadata(index=0)
    with pytest.raises(ValueError):
        WindowMetadata(index=0, start=START, end=START)
    assert WindowMetadata.load(time_window(2).export()) == time_window(2)


def write_dataset(path, minutes):
    times = [(START + pd.Timedelta(minutes=m)).isoformat() for m in minutes]
    pd.DataFrame({"TIME_FIRST": times, "SRC_IP": "10.0.0.1"}).to_csv(path, index=False)


def test_time_windows_span_csv_chunks(tmp_path):
    path = tmp_path / "flows.csv"
    write_dataset(path, [0, 1, 14, 15, 16, 31, 44, 50])

    windows = list(
        TimeWindowIterator(path, ",", "TIME_FIRST", "15min", read_chunk_size=2)
    )

    assert [len(window.flows) for window in windows] == [3, 2, 2, 1]
    assert [window.metadata.index for window in windows] == [0, 1, 2, 3]
    assert windows[1].metadata.start == START + pd.Timedelta(minutes=15)


def test_unsorted_time_windows_are_rejected(tmp_path):
    path = tmp_path / "flows.csv"
    write_dataset(path, [20, 0])

    with pytest.raises(ValueError, match="sorted"):
        list(TimeWindowIterator(path, ",", "TIME_FIRST", "15min"))


def test_row_windows(tmp_path):
    path = tmp_path / "flows.csv"
    write_dataset(path, range(5))

    windows = list(RowWindowIterator(path, ",", 2))

    assert [(w.metadata.row_start, w.metadata.row_end) for w in windows] == [(0, 1), (2, 3), (4, 4)]


def test_resolve_votes_per_annotator():
    results = [
        WindowResult(time_window(index), [observation("10.0.0.1", family)])
        for index, family in enumerate(["linux", "linux", None])
    ]

    (ip,) = WindowResolver().resolve(results)

    assert ip.annotations["sni"].os_family == "linux"
    assert ip.data["window_voting"]["windows"] == 3
    assert len(ip.window_results) == 3
    assert ip.multi_device == []


def test_resolve_keeps_multi_device_window_and_os_conflict():
    flagged = [["MAC", ["aa", "bb"]]]
    results = [
        WindowResult(time_window(0), [observation("10.0.0.1", "linux")]),
        WindowResult(time_window(1), [observation("10.0.0.1", "windows", flagged)]),
    ]

    (ip,) = WindowResolver().resolve(results)

    reasons = {evidence[1]["reason"]: evidence[1] for evidence in ip.multi_device}
    assert reasons["multi_device_window"]["window_index"] == 1
    assert reasons["multi_device_window"]["evidence"] == flagged
    assert "incompatible_os_observations" in reasons


def test_extend_appends_only_unseen():
    (previous,) = WindowResolver().resolve([WindowResult(time_window(0), [observation("10.0.0.1", "linux")])])
    new = [
        WindowResult(time_window(0), [observation("10.0.0.1", "windows")]),
        WindowResult(time_window(1), [observation("10.0.0.1", "linux")]),
    ]

    merged, appended = WindowResolver().extend([previous], new, window_size="15min")

    assert appended == {"10.0.0.1"}
    assert [result.metadata.index for result in merged] == [0, 1]
    assert merged[0].observations[0].annotations["sni"].os_family == "linux"


def test_extend_rejects_other_window_size():
    (previous,) = WindowResolver().resolve([WindowResult(time_window(0), [observation("10.0.0.1")])])

    with pytest.raises(ValueError, match="window size"):
        WindowResolver().extend([previous], [], window_size="5min")


def windowing_config(**windowing):
    config = daf_config()
    config["daf"]["windowing"] = windowing
    return config


@pytest.mark.parametrize(
    "windowing",
    [
        {"enabled": "yes"},
        {"enabled": True, "type": "days", "size": 1},
        {"enabled": True, "type": "rows", "size": 0},
        {"enabled": True, "type": "time", "size": "15min"},
        {"enabled": True, "type": "time", "size": "-1min", "timestamp_field": "T"},
        {"enabled": True, "type": "rows", "size": 10, "consensus": "unanimous"},
        {"enabled": True, "type": "rows", "size": 10, "consensus": "threshold", "threshold": 0},
    ],
)
def test_invalid_window_config_is_rejected(windowing):
    with pytest.raises(ConfigError):
        WindowConfig(windowing_config(**windowing))


def test_window_config():
    assert not WindowConfig.is_enabled(daf_config())
    assert not WindowConfig(windowing_config(enabled=False)).enabled

    config = WindowConfig(
        windowing_config(
            enabled=True, type="time", size="15min", timestamp_field="TIME_FIRST",
            consensus="threshold", threshold=0.7,
        )
    )

    assert config.enabled and config.type == "time"
    assert config.voting().export() == {"voting": "threshold", "threshold": 0.7}
    assert isinstance(config.windows("flows.csv", ","), TimeWindowIterator)
    rows = WindowConfig(windowing_config(enabled=True, type="rows", size=10))
    assert rows.section["consensus"] == "majority"
    assert isinstance(rows.windows("flows.csv", ","), RowWindowIterator)


def test_resolver_uses_configured_voting():
    results = [
        WindowResult(time_window(index), [observation("10.0.0.1", family)])
        for index, family in enumerate(["linux", "linux", "windows"])
    ]

    (majority,) = WindowResolver().resolve(results)
    (strict,) = WindowResolver(WindowVoting("threshold", 0.7)).resolve(results)

    assert majority.annotations["sni"].os_family == "linux"
    assert strict.annotations["sni"].os_family is None
    assert strict.data["window_voting"]["threshold"] == 0.7
