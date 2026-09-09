#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: windows.py
Description: Splits flow datasets into windows and combines their IP results.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import pandas as pd

from annotation import Annotation
from config import ConfigError, Configurable, Requirement
from ip import IP


@dataclass(frozen=True)
class WindowMetadata:
    """Describe the bounds of one window.

    A window has either time bounds (``start`` inclusive, ``end`` exclusive) or row
    bounds (``row_start`` and ``row_end`` inclusive).

    Attributes
    ----------
    index : int
        Sequential index of the window.
    start, end : pd.Timestamp, optional
        Time bounds of a time window.
    row_start, row_end : int, optional
        Row bounds of a row window.
    """

    index: int
    start: Optional[pd.Timestamp] = None
    end: Optional[pd.Timestamp] = None
    row_start: Optional[int] = None
    row_end: Optional[int] = None

    def __post_init__(self) -> None:
        """Ensure that metadata describes exactly one valid window type.

        Raises
        ------
        ValueError
            If the bounds are missing, mixed or not increasing.
        """

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
        """Return JSON-serializable metadata, omitting unused bounds.

        Returns
        -------
        dict
            Window index and its bounds.
        """

        result = {"window_index": self.index}
        if self.start is not None:
            result["start"] = self.start.isoformat()
            result["end"] = self.end.isoformat()
        if self.row_start is not None:
            result["row_start"] = self.row_start
            result["row_end"] = self.row_end
        return result

    @classmethod
    def load(cls, data: dict) -> WindowMetadata:
        """Load window metadata from an exported window result.

        Parameters
        ----------
        data : dict
            Exported window result, see :meth:`export`.

        Returns
        -------
        WindowMetadata
            Loaded metadata.
        """

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
    """A flow DataFrame and the bounds that selected it.

    Attributes
    ----------
    metadata : WindowMetadata
        Bounds of the window.
    flows : pd.DataFrame
        Flows of the window.
    """

    metadata: WindowMetadata
    flows: pd.DataFrame


@dataclass(frozen=True)
class WindowObservation:
    """Compact state of one IP in one window, used for window voting and export.

    Only results of flow-based modules are stored. IP-based modules run once per IP
    after all windows are processed.

    Attributes
    ----------
    ip_address : str
        IP address.
    annotations : dict
        Annotations of flow-based modules in the window, keyed by annotation name.
    multi_device : list
        Multi-device evidence found in the window.
    detections : dict
        Results of detectors in the window, keyed by detector name.
    """

    ip_address: str
    annotations: Dict[str, Annotation]
    multi_device: list
    detections: dict = field(default_factory=dict)

    @classmethod
    def from_ip(cls, ip: IP, detector_names: Iterable[str] = ()) -> WindowObservation:
        """Copy the window state of an IP processed by flow-based modules.

        Parameters
        ----------
        ip : IP
            IP object annotated in one window.
        detector_names : Iterable[str], optional
            Names of detectors whose results are copied from ``ip.data``.

        Returns
        -------
        WindowObservation
            Compact observation.
        """

        return cls(
            ip_address=str(ip.ip_addr),
            annotations=deepcopy(ip.annotations),
            multi_device=deepcopy(ip.multi_device),
            detections={
                name: deepcopy(ip.data[name]) for name in detector_names if name in ip.data
            },
        )

    @classmethod
    def load(cls, ip_address: str, data: dict) -> WindowObservation:
        """Load one compact observation from an exported window result.

        Parameters
        ----------
        ip_address : str
            IP address of the observation.
        data : dict
            Exported window result, see :meth:`export`.

        Returns
        -------
        WindowObservation
            Loaded observation.
        """

        return cls(
            ip_address=ip_address,
            annotations={
                name: Annotation.load(annotation)
                for name, annotation in data.get("annotations", {}).items()
            },
            multi_device=deepcopy(data.get("multi_device", [])),
            detections=deepcopy(data.get("detections", {})),
        )

    def export(self, metadata: WindowMetadata) -> dict:
        """Export the observation together with its window bounds.

        Parameters
        ----------
        metadata : WindowMetadata
            Bounds of the window of the observation.

        Returns
        -------
        dict
            JSON-serializable window result.
        """

        result = metadata.export()
        result["annotations"] = {
            name: annotation.export() for name, annotation in self.annotations.items()
        }
        result["multi_device"] = deepcopy(self.multi_device)
        result["detections"] = deepcopy(self.detections)
        return result


@dataclass
class WindowResult:
    """Compact IP observations produced by processing one window.

    Attributes
    ----------
    metadata : WindowMetadata
        Bounds of the window.
    observations : list
        :class:`WindowObservation` of every IP in the window.
    """

    metadata: WindowMetadata
    observations: List[WindowObservation]

    @classmethod
    def from_ips(
        cls,
        metadata: WindowMetadata,
        ip_addresses: Iterable[IP],
        detector_names: Iterable[str] = (),
    ) -> WindowResult:
        """Capture compact observations without retaining module flow data.

        Parameters
        ----------
        metadata : WindowMetadata
            Bounds of the window.
        ip_addresses : Iterable[IP]
            IP objects annotated in the window.
        detector_names : Iterable[str], optional
            Names of detectors whose results are kept.

        Returns
        -------
        WindowResult
            Result of the window.
        """

        detector_names = tuple(detector_names)
        return cls(
            metadata,
            [WindowObservation.from_ip(ip, detector_names) for ip in ip_addresses],
        )


class RowWindowIterator:
    """Iterate over consecutive CSV row chunks as DAF windows.

    Attributes
    ----------
    dataset : str or pathlib.Path
        Path to the CSV dataset.
    delimiter : str
        CSV delimiter.
    size : int
        Number of rows of one window.
    """

    def __init__(self, dataset: Union[str, Path], delimiter: str, size: int) -> None:
        """Initialize the iterator, see the class attributes."""

        self.dataset = dataset
        self.delimiter = delimiter
        self.size = size

    def __iter__(self) -> Iterator[FlowWindow]:
        """Yield consecutive row windows.

        Yields
        ------
        FlowWindow
            Consecutive row windows.
        """

        row_start = 0
        with pd.read_csv(
            self.dataset,
            delimiter=self.delimiter,
            low_memory=False,
            chunksize=self.size,
        ) as chunks:
            for index, flows in enumerate(chunks):
                row_end = row_start + len(flows) - 1
                yield FlowWindow(
                    WindowMetadata(index=index, row_start=row_start, row_end=row_end),
                    flows,
                )
                row_start = row_end + 1


class TimeWindowIterator:
    """Iterate over fixed time windows of a timestamp-sorted CSV.

    The last bucket of each physical CSV chunk is buffered because that logical
    time window may continue in the next chunk.

    Attributes
    ----------
    dataset : str or pathlib.Path
        Path to the CSV dataset sorted by ``timestamp_field``.
    delimiter : str
        CSV delimiter.
    timestamp_field : str
        Name of the timestamp column.
    size : object
        Window size, see :meth:`parse_duration`.
    read_chunk_size : int
        Number of rows read from the CSV at once.
    """

    def __init__(
        self,
        dataset: Union[str, Path],
        delimiter: str,
        timestamp_field: str,
        size: object,
        read_chunk_size: int = 100_000,
    ) -> None:
        """Initialize the iterator, see the class attributes."""

        self.dataset = dataset
        self.delimiter = delimiter
        self.timestamp_field = timestamp_field
        self.size = size
        self.read_chunk_size = read_chunk_size

    @staticmethod
    def parse_duration(value: object) -> pd.Timedelta:
        """Parse a positive fixed duration accepted by pandas.

        Parameters
        ----------
        value : int, float, str or pd.Timedelta
            Duration. Numbers are seconds, strings use pandas syntax (e.g. ``15min``).

        Returns
        -------
        pd.Timedelta
            Parsed duration.

        Raises
        ------
        ValueError
            If the value is not a positive duration.
        """

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

    @staticmethod
    def assign_time_buckets(
        flows: pd.DataFrame,
        *,
        timestamp_field: str,
        size: object,
    ) -> Tuple[pd.Series, pd.Series]:
        """Parse timestamps and assign the shared fixed-duration bucket starts.

        Parameters
        ----------
        flows : pd.DataFrame
            Flow records.
        timestamp_field : str
            Name of the timestamp column.
        size : object
            Window size, see :func:`parse_duration`.

        Returns
        -------
        tuple
            Parsed UTC timestamps and the start of the bucket of every flow.

        Raises
        ------
        KeyError
            If the timestamp column is missing.
        ValueError
            If a timestamp is missing.
        """

        if timestamp_field not in flows.columns:
            raise KeyError(f"Timestamp column {timestamp_field!r} is missing")

        timestamps = pd.to_datetime(flows[timestamp_field], errors="raise", utc=True)
        if timestamps.isna().any():
            raise ValueError(f"Timestamp column {timestamp_field!r} contains missing values")
        return timestamps, timestamps.dt.floor(TimeWindowIterator.parse_duration(size))

    def __iter__(self) -> Iterator[FlowWindow]:
        """Yield the non-empty time windows in time order.

        Yields
        ------
        FlowWindow
            Time windows.

        Raises
        ------
        ValueError
            If the dataset is not sorted by timestamp.
        """

        duration = self.parse_duration(self.size)
        pending: Optional[Tuple[pd.DataFrame, pd.Series]] = None
        previous_timestamp: Optional[pd.Timestamp] = None
        window_index = 0

        with pd.read_csv(
            self.dataset,
            delimiter=self.delimiter,
            low_memory=False,
            chunksize=self.read_chunk_size,
        ) as chunks:
            for flows in chunks:
                timestamps, buckets = self.assign_time_buckets(
                    flows,
                    timestamp_field=self.timestamp_field,
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


class WindowVoting:
    """Combine values observed in several windows into one value.

    Only non-empty values vote. The most common value wins if its share of the votes
    passes the consensus rule, otherwise the voting abstains (returns None). A tie of
    the most common values always abstains.

    - ``majority``: the share must be greater than 1/2.
    - ``threshold``: the share must be at least ``threshold``.

    Attributes
    ----------
    method : str
        ``"majority"`` or ``"threshold"``.
    threshold : float
        Minimal share of votes of the ``threshold`` method, in (0, 1].
    """

    METHODS = ("majority", "threshold")

    def __init__(self, method: str = "majority", threshold: float = 0.5) -> None:
        """Initialize the voting.

        Parameters
        ----------
        method : str, optional
            ``"majority"`` (default) or ``"threshold"``.
        threshold : float, optional
            Minimal share of votes of the ``threshold`` method, by default 0.5.

        Raises
        ------
        ValueError
            If the method is unknown or the threshold is not in (0, 1].
        """

        if method not in self.METHODS:
            raise ValueError(f"Unknown window voting method {method!r}, supported: {self.METHODS}")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise ValueError("Window voting threshold must be a number")
        if not 0 < threshold <= 1:
            raise ValueError("Window voting threshold must be in the interval (0, 1]")
        self.method = method
        self.threshold = float(threshold)

    @classmethod
    def from_config(cls, windowing: dict) -> WindowVoting:
        """Create the voting from the ``daf.windowing`` configuration.

        Parameters
        ----------
        windowing : dict
            Windowing configuration with optional ``consensus`` and ``threshold``.

        Returns
        -------
        WindowVoting
            Configured voting.
        """

        return cls(windowing.get("consensus", "majority"), windowing.get("threshold", 0.5))

    def accepts(self, count: int, total: int) -> bool:
        """Return whether ``count`` of ``total`` votes passes the consensus rule.

        Parameters
        ----------
        count : int
            Votes of the most common value.
        total : int
            All non-empty votes.

        Returns
        -------
        bool
            True if the value is accepted.
        """

        if self.method == "majority":
            return count > total / 2
        return count / total >= self.threshold

    def vote(self, values: Iterable[Optional[str]]) -> Optional[str]:
        """Vote for one value.

        Parameters
        ----------
        values : Iterable[str or None]
            Values observed in the windows. Empty values abstain.

        Returns
        -------
        str or None
            The accepted value, or None.
        """

        votes = [value for value in values if value]
        if not votes:
            return None
        ranking = Counter(votes).most_common(2)
        value, count = ranking[0]
        if len(ranking) > 1 and ranking[1][1] == count:
            return None
        return value if self.accepts(count, len(votes)) else None

    def vote_annotation(self, annotations: List[Annotation]) -> Annotation:
        """Build a hierarchical annotation from window annotations.

        Child fields vote only within observations matching the winning parent
        (group -> class, os_family -> os_type -> os_version).

        Parameters
        ----------
        annotations : list
            Annotations of one annotator in the windows.

        Returns
        -------
        Annotation
            Voted annotation.
        """

        group = self.vote(annotation.group for annotation in annotations)
        group_matches = [annotation for annotation in annotations if annotation.group == group]
        device_class = (
            self.vote(annotation._class for annotation in group_matches) if group else None
        )

        os_family = self.vote(annotation.os_family for annotation in annotations)
        family_matches = [
            annotation for annotation in annotations if annotation.os_family == os_family
        ]
        os_type = self.vote(annotation.os_type for annotation in family_matches) if os_family else None
        type_matches = [annotation for annotation in family_matches if annotation.os_type == os_type]
        os_version = (
            self.vote(annotation.os_version for annotation in type_matches) if os_type else None
        )

        return Annotation(group, device_class, os_family, os_type, os_version)

    def export(self) -> dict:
        """Return the voting configuration for the exported IP data.

        Returns
        -------
        dict
            ``voting`` method and, for the threshold method, the ``threshold``.
        """

        result = {"voting": self.method}
        if self.method == "threshold":
            result["threshold"] = self.threshold
        return result


class WindowConfig(Configurable):
    """Configuration of windowed processing, the ``daf.windowing`` section.

    Attributes
    ----------
    section : dict
        Checked ``daf.windowing`` section, ``{"enabled": False}`` if it is missing.
    """

    REQUIREMENTS = (
        Requirement("enabled", bool),
        Requirement("type", str, choices=("rows", "time"), required_if={"enabled": True}),
        Requirement("size", (int, float, str), required_if={"enabled": True}),
        Requirement("timestamp_field", str, required_if={"enabled": True, "type": "time"}),
        Requirement("consensus", str, default="majority", choices=WindowVoting.METHODS),
        Requirement(
            "threshold",
            (int, float),
            default=0.5,
            check=lambda value: None if 0 < value <= 1 else "must be in the interval (0, 1]",
        ),
    )

    def __init__(self, config: dict) -> None:
        """Check the windowing configuration.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.

        Raises
        ------
        ConfigError
            If the windowing configuration is invalid.
        """

        section = config["daf"].get("windowing")
        if section is None:
            section = {"enabled": False}
        self.section = self.check_config(section, "daf.windowing")
        if not self.enabled:
            return

        size = self.section["size"]
        if self.section["type"] == "rows":
            if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
                raise ConfigError("daf.windowing.size: row window size must be a positive integer")
            return
        try:
            TimeWindowIterator.parse_duration(size)
        except ValueError as error:
            raise ConfigError(f"daf.windowing.size: {error}") from error

    @classmethod
    def is_enabled(cls, config: dict) -> bool:
        """Return whether windowed processing is enabled in a configuration.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.

        Returns
        -------
        bool
            True if ``daf.windowing.enabled`` is True.
        """

        return cls(config).enabled

    @property
    def enabled(self) -> bool:
        """Return whether windowed processing is enabled."""

        return self.section["enabled"]

    @property
    def type(self) -> str:
        """Return the window type, ``rows`` or ``time``."""

        return self.section["type"]

    @property
    def size(self) -> object:
        """Return the window size, rows or a duration."""

        return self.section["size"]

    def voting(self) -> WindowVoting:
        """Create the voting of the configured consensus.

        Returns
        -------
        WindowVoting
            Voting of ``consensus`` with ``threshold``.
        """

        return WindowVoting(self.section["consensus"], self.section["threshold"])

    def windows(self, dataset: Union[str, Path], delimiter: str):
        """Create the window iterator of the dataset.

        Parameters
        ----------
        dataset : str or pathlib.Path
            Path to the CSV dataset.
        delimiter : str
            CSV delimiter.

        Returns
        -------
        RowWindowIterator or TimeWindowIterator
            Iterator over the windows.
        """

        if self.type == "rows":
            return RowWindowIterator(dataset, delimiter, self.size)
        return TimeWindowIterator(dataset, delimiter, self.section["timestamp_field"], self.size)


class WindowResolver:
    """Combine the results of all windows into one IP object per IP address.

    Attributes
    ----------
    voting : WindowVoting
        Voting combining the annotations of the windows.
    """

    def __init__(self, voting: Optional[WindowVoting] = None) -> None:
        """Initialize the resolver.

        Parameters
        ----------
        voting : WindowVoting, optional
            Voting combining the windows, majority voting by default.
        """

        self.voting = voting or WindowVoting()

    @staticmethod
    def os_annotations_conflict(left: Annotation, right: Annotation) -> bool:
        """Return whether two non-empty OS descriptions contradict each other."""

        for field_name in ("os_family", "os_type", "os_version"):
            left_value = getattr(left, field_name)
            right_value = getattr(right, field_name)
            if not left_value or not right_value:
                continue
            if left_value != right_value:
                return True
        return False

    @staticmethod
    def has_os_conflict(annotations: List[Annotation]) -> bool:
        """Return whether any two window annotations describe different operating systems."""

        os_annotations = [
            annotation
            for annotation in annotations
            if any((annotation.os_family, annotation.os_type, annotation.os_version))
        ]
        return any(
            WindowResolver.os_annotations_conflict(left, right)
            for index, left in enumerate(os_annotations)
            for right in os_annotations[index + 1 :]
        )

    @staticmethod
    def first_multi_device_window(entries: List[Tuple[WindowMetadata, WindowObservation]]) -> Optional[int]:
        """Return the index of the first window that flagged the IP as a multi-device.

        Parameters
        ----------
        entries : list
            ``(metadata, observation)`` pairs of one IP.

        Returns
        -------
        int or None
            Window index, or None if no window flagged the IP.
        """

        flagged = [metadata.index for metadata, observation in entries if observation.multi_device]
        return min(flagged) if flagged else None

    def resolve(self, results: Iterable[WindowResult]) -> List[IP]:
        """Combine window results into one IP object per IP address.

        For every flow-based annotation name, the annotations of all windows are combined
        by hierarchical voting (see :class:`WindowVoting`) and stored as the annotation of the final IP. The
        annotations of IP-based modules and the final annotation are added afterwards by
        the pipeline.

        An IP flagged as a multi-device in any window stays flagged; such IPs are not
        processed in later windows. An IP whose windows describe incompatible operating
        systems in one annotator is flagged as well.

        Parameters
        ----------
        results : Iterable[WindowResult]
            Results of all windows.

        Returns
        -------
        list
            IP objects with voted flow annotations, ``window_results`` and the voting
            summary in ``data["window_voting"]``.
        """

        by_ip: Dict[str, List[Tuple[WindowMetadata, WindowObservation]]] = {}
        for result in results:
            for observation in result.observations:
                by_ip.setdefault(observation.ip_address, []).append((result.metadata, observation))

        final_ips = []
        for ip_address, entries in by_ip.items():
            final_ip = IP(ip_address)

            annotation_names = list(
                dict.fromkeys(name for _, observation in entries for name in observation.annotations)
            )
            os_conflict = False
            for name in annotation_names:
                annotations = [
                    observation.annotations[name]
                    for _, observation in entries
                    if name in observation.annotations
                ]
                final_ip.add_annotation(name, self.voting.vote_annotation(annotations))
                os_conflict = os_conflict or self.has_os_conflict(annotations)

            multi_device_window = self.first_multi_device_window(entries)
            final_ip.add_data(
                "window_voting",
                {
                    **self.voting.export(),
                    "windows": len(entries),
                    "multi_device_window": multi_device_window,
                    "os_conflict": os_conflict,
                },
            )

            for metadata, observation in entries:
                final_ip.window_results.append(observation.export(metadata))

            if multi_device_window is not None:
                evidence = next(
                    observation.multi_device
                    for metadata, observation in entries
                    if metadata.index == multi_device_window
                )
                final_ip.multi_device.append(
                    [
                        "window_voting",
                        {
                            "reason": "multi_device_window",
                            "window_index": multi_device_window,
                            "evidence": deepcopy(evidence),
                        },
                    ]
                )
            if os_conflict:
                final_ip.multi_device.append(
                    ["window_voting", {"reason": "incompatible_os_observations"}]
                )
            final_ips.append(final_ip)

        return final_ips

    def extend(
        self,
        previous_ips: Iterable[IP],
        new_results: Iterable[WindowResult],
        *,
        window_size: object,
    ) -> Tuple[List[WindowResult], set]:
        """Append observations whose IP and window start were not previously saved.

        Parameters
        ----------
        previous_ips : Iterable[IP]
            IPs loaded from a previous windowed run, with ``window_results``.
        new_results : Iterable[WindowResult]
            Results of newly processed windows.
        window_size : object
            Configured time window size, see :func:`parse_duration`.

        Returns
        -------
        tuple
            Merged window results ordered by window start and the set of IP addresses
            with appended observations.

        Raises
        ------
        ValueError
            If saved results are not time windows of the configured size, or contain
            duplicate observations.
        """

        expected_duration = TimeWindowIterator.parse_duration(window_size)
        buckets: Dict[pd.Timestamp, Tuple[pd.Timestamp, Dict[str, WindowObservation]]] = {}

        def add_observation(
            metadata: WindowMetadata,
            observation: WindowObservation,
            *,
            append_only: bool,
        ) -> bool:
            """Add an observation to its bucket, return False for skipped duplicates."""

            if metadata.start is None or metadata.end is None:
                raise ValueError("Windowed reannotation requires timestamped window results")
            if metadata.end - metadata.start != expected_duration:
                raise ValueError("Saved window duration does not match the configured window size")

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


__all__ = [
    "FlowWindow",
    "RowWindowIterator",
    "TimeWindowIterator",
    "WindowConfig",
    "WindowMetadata",
    "WindowObservation",
    "WindowResolver",
    "WindowResult",
    "WindowVoting",
]
