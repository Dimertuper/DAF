#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: windows.py
Description: Splits flow datasets into windows and combines their IP results.
"""

from collections import Counter
from collections.abc import Iterable, Iterator
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from annotation import Annotation
from ip import IP


@dataclass(frozen=True)
class WindowMetadata:
    """Describe window data with one DAF execution."""

    index: int
    start: pd.Timestamp | None = None
    end: pd.Timestamp | None = None
    row_start: int | None = None
    row_end: int | None = None

    def __post_init__(self) -> None:
        """Ensure that metadata describes exactly one valid window type."""

        if self.index < 0:
            raise ValueError("Window index cannot be negative")

        has_time_bound = self.start is not None or self.end is not None
        has_row_bound = self.row_start is not None or self.row_end is not None
        if has_time_bound == has_row_bound:
            raise ValueError("A window must have either time bounds or row bounds")

        if has_time_bound:
            if self.start is None or self.end is None or self.start >= self.end:
                raise ValueError("A time window requires increasing start and end bounds")
        elif (
            self.row_start is None
            or self.row_end is None
            or self.row_start < 0
            or self.row_start > self.row_end
        ):
            raise ValueError("A row window requires valid inclusive row bounds")

    def export(self) -> dict:
        """Return JSON-serializable metadata, omitting unused bounds."""

        result = {"window_index": self.index}
        if self.start is not None:
            result["start"] = self.start.isoformat()
            result["end"] = self.end.isoformat()
        if self.row_start is not None:
            result["row_start"] = self.row_start
            result["row_end"] = self.row_end
        return result

    @classmethod
    def load(cls, data: dict) -> "WindowMetadata":
        """Load window metadata from an exported window result."""

        if "start" in data or "end" in data:
            return cls(
                index=data["window_index"],
                start=pd.to_datetime(data.get("start"), errors="raise", utc=True),
                end=pd.to_datetime(data.get("end"), errors="raise", utc=True),
            )
        return cls(
            index=data["window_index"],
            row_start=data.get("row_start"),
            row_end=data.get("row_end"),
        )


@dataclass
class FlowWindow:
    """A flow DataFrame and the bounds that selected it."""

    metadata: WindowMetadata
    flows: pd.DataFrame


@dataclass(frozen=True)
class WindowObservation:
    """Compact IP state required for window voting and result export."""

    ip_address: str
    annotation: Annotation
    multi_device: list
    nat_result: dict | None
    hand_miss: list
    one_miss: list

    @classmethod
    def from_ip(cls, ip: IP) -> "WindowObservation":
        """Copy only the IP fields consumed after its window is processed."""

        nat_result = ip.data.get("nat_detector")
        return cls(
            ip_address=str(ip.ip_addr),
            annotation=deepcopy(ip.final_annotation),
            multi_device=deepcopy(ip.multi_device),
            nat_result=deepcopy(nat_result) if isinstance(nat_result, dict) else None,
            hand_miss=deepcopy(ip.hand_miss),
            one_miss=deepcopy(ip.one_miss),
        )

    @classmethod
    def load(cls, ip_address: str, data: dict) -> "WindowObservation":
        """Load one compact observation from an exported window result."""

        window_data = data.get("data", {})
        nat_result = window_data.get("nat_detector")
        return cls(
            ip_address=ip_address,
            annotation=Annotation.load(data.get("annotation", {})),
            multi_device=deepcopy(data.get("multi_device", [])),
            nat_result=deepcopy(nat_result) if isinstance(nat_result, dict) else None,
            hand_miss=[],
            one_miss=[],
        )


@dataclass
class WindowResult:
    """Compact IP observations produced by one ordinary DAF execution."""

    metadata: WindowMetadata
    observations: list[WindowObservation]

    @classmethod
    def from_ips(cls, metadata: WindowMetadata, ip_addresses: Iterable[IP]) -> "WindowResult":
        """Capture compact observations without retaining module flow data."""

        return cls(metadata, [WindowObservation.from_ip(ip) for ip in ip_addresses])


def extend_time_window_results(
    previous_ips: Iterable[IP],
    new_results: Iterable[WindowResult],
    *,
    window_size: object,
) -> tuple[list[WindowResult], set[str]]:
    """Append observations whose IP and timestamp were not previously saved."""

    expected_duration = parse_duration(window_size)
    buckets: dict[
        pd.Timestamp,
        tuple[pd.Timestamp, dict[str, WindowObservation]],
    ] = {}

    def add_observation(
        metadata: WindowMetadata,
        observation: WindowObservation,
        *,
        append_only: bool,
    ) -> bool:
        if metadata.start is None or metadata.end is None:
            raise ValueError("Windowed reannotation requires timestamped window results")
        if metadata.end - metadata.start != expected_duration:
            raise ValueError(
                "Saved window duration does not match the configured window size"
            )

        if metadata.start not in buckets:
            buckets[metadata.start] = (metadata.end, {})
        saved_end, observations = buckets[metadata.start]
        if saved_end != metadata.end:
            raise ValueError(
                f"Window starting at {metadata.start.isoformat()} has inconsistent end times"
            )
        if observation.ip_address in observations:
            if append_only:
                return False
            raise ValueError(
                "Saved window results contain a duplicate IP and timestamp: "
                f"{observation.ip_address}, {metadata.start.isoformat()}"
            )
        observations[observation.ip_address] = observation
        return True

    # Saved duplicates indicate corrupt history; new duplicates are simply skipped.
    for ip in previous_ips:
        for data in ip.window_results:
            add_observation(
                WindowMetadata.load(data),
                WindowObservation.load(str(ip.ip_addr), data),
                append_only=False,
            )

    appended_ips = set()
    for result in new_results:
        for observation in result.observations:
            if add_observation(result.metadata, observation, append_only=True):
                appended_ips.add(observation.ip_address)

    merged_results = []
    for index, start in enumerate(sorted(buckets)):
        end, observations = buckets[start]
        merged_results.append(
            WindowResult(
                WindowMetadata(index=index, start=start, end=end),
                list(observations.values()),
            )
        )
    return merged_results, appended_ips


def parse_duration(value: object) -> pd.Timedelta:
    """Parse a positive fixed duration accepted by pandas."""

    try:
        if isinstance(value, (int, float)):  # Numeric sizes are seconds.
            duration = pd.Timedelta(seconds=value)
        else:  # Strings use pandas duration syntax.
            duration = pd.Timedelta(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid time window size: {value!r}") from error
    if pd.isna(duration) or duration <= pd.Timedelta(0):
        raise ValueError("Time window size must be greater than zero")
    return duration


def iter_row_windows(
    dataset: str | Path,
    *,
    delimiter: str,
    size: int,
) -> Iterator[FlowWindow]:
    """Yield consecutive CSV row chunks as DAF windows."""

    row_start = 0
    with pd.read_csv(
        dataset,
        delimiter=delimiter,
        low_memory=False,
        chunksize=size,
    ) as chunks:
        for index, flows in enumerate(chunks):
            row_end = row_start + len(flows) - 1
            yield FlowWindow(
                WindowMetadata(index=index, row_start=row_start, row_end=row_end),
                flows,
            )
            row_start = row_end + 1


def assign_time_buckets(
    flows: pd.DataFrame,
    *,
    timestamp_field: str,
    size: object,
) -> tuple[pd.Series, pd.Series]:
    """Parse timestamps and assign the shared fixed-duration bucket starts."""

    if timestamp_field not in flows.columns:
        raise KeyError(f"Timestamp column {timestamp_field!r} is missing")

    timestamps = pd.to_datetime(flows[timestamp_field], errors="raise", utc=True)
    if timestamps.isna().any():
        raise ValueError(f"Timestamp column {timestamp_field!r} contains missing values")
    return timestamps, timestamps.dt.floor(parse_duration(size))


def iter_time_windows(
    dataset: str | Path,
    *,
    delimiter: str,
    timestamp_field: str,
    size: object,
    read_chunk_size: int = 100_000,
) -> Iterator[FlowWindow]:
    """Yield fixed time windows from a timestamp-sorted CSV.

    The last bucket of each physical CSV chunk is buffered because that logical
    time window may continue in the next chunk.
    """

    duration = parse_duration(size)
    pending: tuple[pd.DataFrame, pd.Series] | None = None
    previous_timestamp: pd.Timestamp | None = None
    window_index = 0

    with pd.read_csv(
        dataset,
        delimiter=delimiter,
        low_memory=False,
        chunksize=read_chunk_size,
    ) as chunks:
        for flows in chunks:
            timestamps, buckets = assign_time_buckets(
                flows,
                timestamp_field=timestamp_field,
                size=duration,
            )
            if not timestamps.is_monotonic_increasing:
                raise ValueError("Time-windowed input must be sorted by timestamp")
            if previous_timestamp is not None and timestamps.iloc[0] < previous_timestamp:
                raise ValueError("Time-windowed input must be sorted by timestamp")
            previous_timestamp = timestamps.iloc[-1]

            if pending is not None:
                pending_flows, pending_buckets = pending
                flows = pd.concat([pending_flows, flows], ignore_index=True)
                buckets = pd.concat([pending_buckets, buckets], ignore_index=True)
            else:
                flows = flows.reset_index(drop=True)
                buckets = buckets.reset_index(drop=True)

            # The final bucket may continue in the next physical CSV chunk.
            last_bucket = buckets.iloc[-1]
            complete_mask = buckets != last_bucket
            complete = flows[complete_mask]
            complete_buckets = buckets[complete_mask]
            pending = flows[~complete_mask], buckets[~complete_mask]

            for start, bucket in complete.groupby(complete_buckets, sort=False):
                yield FlowWindow(
                    WindowMetadata(index=window_index, start=start, end=start + duration),
                    bucket,
                )
                window_index += 1

    if pending is not None:
        pending_flows, pending_buckets = pending
        start = pending_buckets.iloc[0]
        yield FlowWindow(
            WindowMetadata(index=window_index, start=start, end=start + duration),
            pending_flows,
        )


def iter_flow_windows(
    dataset: str | Path,
    *,
    delimiter: str,
    config: dict,
) -> Iterator[FlowWindow]:
    """Select the configured window iterator."""

    if config["type"] == "rows":
        yield from iter_row_windows(dataset, delimiter=delimiter, size=config["size"])
        return
    if config["type"] == "time":
        yield from iter_time_windows(
            dataset,
            delimiter=delimiter,
            timestamp_field=config["timestamp_field"],
            size=config["size"],
        )
        return
    raise ValueError("Window type must be 'rows' or 'time'")


def _majority(values: Iterable[str | None]) -> str | None:
    votes = [value for value in values if value]
    if not votes:
        return None
    value, count = Counter(votes).most_common(1)[0]
    if count > len(votes) / 2:
        return value
    return None


def _majority_annotation(annotations: list[Annotation]) -> Annotation:
    """Build a hierarchical majority annotation from completed annotations."""

    # Child fields vote only within observations matching the winning parent.
    group = _majority(annotation.group for annotation in annotations)
    group_matches = [annotation for annotation in annotations if annotation.group == group]
    device_class = _majority(annotation._class for annotation in group_matches) if group else None

    os_family = _majority(annotation.os_family for annotation in annotations)
    family_matches = [
        annotation for annotation in annotations if annotation.os_family == os_family
    ]
    os_type = _majority(annotation.os_type for annotation in family_matches) if os_family else None
    type_matches = [annotation for annotation in family_matches if annotation.os_type == os_type]
    os_version = (
        _majority(annotation.os_version for annotation in type_matches) if os_type else None
    )

    return Annotation(group, device_class, os_family, os_type, os_version)


def _os_annotations_conflict(left: Annotation, right: Annotation) -> bool:
    """Return whether two non-empty OS descriptions contradict each other."""

    for field in ("os_family", "os_type", "os_version"):
        left_value = getattr(left, field)
        right_value = getattr(right, field)
        if not left_value or not right_value:
            continue
        if left_value != right_value:
            return True
    return False


def _has_os_conflict(annotations: list[Annotation]) -> bool:
    os_annotations = [
        annotation
        for annotation in annotations
        if any((annotation.os_family, annotation.os_type, annotation.os_version))
    ]
    return any(
        _os_annotations_conflict(left, right)
        for index, left in enumerate(os_annotations)
        for right in os_annotations[index + 1 :]
    )


def _is_nat_detector_evidence(evidence: object) -> bool:
    """Return whether evidence was emitted by the NAT detector."""

    return (
        isinstance(evidence, list)
        and evidence
        and str(evidence[0]).lower() == "nat_detector"
    )


def resolve_window_results(results: Iterable[WindowResult]) -> list[IP]:
    """Resolve all window results using majority voting."""

    by_ip: dict[str, list[tuple[WindowMetadata, WindowObservation]]] = {}
    for result in results:
        for observation in result.observations:
            by_ip.setdefault(observation.ip_address, []).append(
                (result.metadata, observation)
            )

    final_ips = []
    for ip_address, entries in by_ip.items():
        observations = [observation for _, observation in entries]
        annotations = [observation.annotation for observation in observations]
        final_ip = IP(ip_address)
        final_ip.final_annotation = _majority_annotation(annotations)

        nat_votes = []
        has_nat_output = False
        annotation_nat = False
        for observation in observations:
            # Explicit detector output takes precedence over legacy evidence.
            nat_marked = any(
                _is_nat_detector_evidence(evidence)
                for evidence in observation.multi_device
            )
            decision = (
                observation.nat_result.get("detected")
                if observation.nat_result is not None
                else None
            )
            if isinstance(decision, bool):
                nat_votes.append(decision)
                has_nat_output = True
            else:
                nat_votes.append(nat_marked)
                has_nat_output = has_nat_output or nat_marked
            annotation_nat = annotation_nat or any(
                not _is_nat_detector_evidence(evidence)
                for evidence in observation.multi_device
            )

        positive_votes = nat_votes.count(True) if has_nat_output else 0
        negative_votes = nat_votes.count(False) if has_nat_output else 0
        detector_nat = positive_votes > negative_votes
        os_conflict = _has_os_conflict(annotations)
        final_ip.add_data(
            "window_voting",
            {
                "voting": "majority",
                "positive_windows": positive_votes,
                "negative_windows": negative_votes,
                "os_conflict": os_conflict,
            },
        )

        for metadata, observation in entries:
            window_result = metadata.export()
            window_result["annotation"] = observation.annotation.export()
            window_result["data"] = (
                {"nat_detector": deepcopy(observation.nat_result)}
                if observation.nat_result is not None
                else {}
            )
            window_result["multi_device"] = deepcopy(observation.multi_device)
            final_ip.window_results.append(window_result)
            final_ip.hand_miss.extend(observation.hand_miss)
            final_ip.one_miss.extend(observation.one_miss)

        if detector_nat:
            final_ip.multi_device.append(
                [
                    "window_voting",
                    {
                        "reason": "nat_detector_majority",
                        "positive_windows": positive_votes,
                        "negative_windows": negative_votes,
                    },
                ]
            )
        if annotation_nat:
            final_ip.multi_device.append(["window_voting", {"reason": "annotation_conflict"}])
        if os_conflict:
            final_ip.multi_device.append(
                ["window_voting", {"reason": "incompatible_os_observations"}]
            )
        final_ips.append(final_ip)

    return final_ips
