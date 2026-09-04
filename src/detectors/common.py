#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: common.py
Description: Shared abstractions for machine-learning detectors.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, Generic, TypeVar

import pandas as pd

from windows import assign_time_buckets, parse_duration

PathLike = str | Path
TableSource = PathLike | pd.DataFrame

InputT = TypeVar("InputT")
FeatureT = TypeVar("FeatureT")


class ProbabilityClassifier(ABC, Generic[InputT, FeatureT]):
    """Apply a decision threshold to a concrete classifier's probability.

    Concrete detector implementations are responsible for loading their model,
    preparing features, and producing the positive-class probability.
    """

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    @property
    def threshold(self) -> float:
        """Return the positive-class decision threshold."""

        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        threshold = float(value)
        if not 0 <= threshold <= 1:
            raise ValueError("Classifier threshold must be between 0 and 1")
        self._threshold = threshold

    def classify(self, data: InputT) -> tuple[bool, float]:
        """Return the threshold decision and positive-class probability."""

        features = self.aggregate(data)
        probability = float(self.predict_probability(features))
        if not 0 <= probability <= 1:
            raise ValueError("Classifier probability must be between 0 and 1")
        return probability >= self.threshold, probability

    @abstractmethod
    def aggregate(self, data: InputT) -> FeatureT:
        """Convert one entity's raw records into one model feature row."""

    @abstractmethod
    def predict_probability(self, features: FeatureT) -> float:
        """Produce a positive-class probability from one feature row."""


def _read_table(data: TableSource, delimiter: str) -> pd.DataFrame:
    """Load a flow or label table from a supported source.

    Parameters
    ----------
    data : str, pathlib.Path, or pd.DataFrame
        Source DataFrame or path to a CSV file.
    delimiter : str
        Field delimiter used when reading a CSV file.

    Returns
    -------
    pd.DataFrame
        A copy of the provided DataFrame or the table loaded from disk.

    """
    if isinstance(data, pd.DataFrame):
        return data.copy()

    return pd.read_csv(Path(data).expanduser(), delimiter=delimiter, low_memory=False)


class IPFlowDataset(Mapping[str, pd.DataFrame]):
    """Expose detector training flows as a mapping grouped by source IP.

    Attributes
    ----------
    flows : pd.DataFrame
        Loaded flow records.
    src_ip_field : str
        Name of the source-IP column.
    """

    def __init__(
        self,
        data: TableSource,
        *,
        src_ip_field: str = "SRC_IP",
        delimiter: str = ",",
    ) -> None:
        """Load flow data and group it by source IP.

        Parameters
        ----------
        data : str, pathlib.Path, or pd.DataFrame
            Flow table or path to a CSV file.
        src_ip_field : str, optional
            Name of the source-IP column, by default ``"SRC_IP"``.
        delimiter : str, optional
            Field delimiter used for CSV files, by default ``,`` (comma).
        """
        self.flows = _read_table(data, delimiter)
        if src_ip_field not in self.flows.columns:
            raise KeyError(f"Source-IP column {src_ip_field!r} is missing")
        self.src_ip_field = src_ip_field
        self._grouped_flows = self.flows.groupby(src_ip_field)
        self._ip_addresses = tuple(self._grouped_flows.groups)

    def __getitem__(self, ip_address: str) -> pd.DataFrame:
        """Return all flows belonging to one source IP."""

        return self._grouped_flows.get_group(ip_address)

    def __iter__(self) -> Iterator[str]:
        """Iterate over source-IP keys."""

        return iter(self._ip_addresses)

    def __len__(self) -> int:
        """Return the number of source-IP groups."""

        return len(self._ip_addresses)

    def agg(self, *args: Any, **kwargs: Any) -> pd.DataFrame | pd.Series:
        """Aggregate each IP group using pandas ``DataFrameGroupBy.agg``.

        Positional and keyword arguments are forwarded unchanged, allowing
        callers to define detector-specific features with pandas aggregation
        functions or named aggregations.
        """

        return self._grouped_flows.agg(*args, **kwargs)

    def apply(
        self, aggregation: Callable[[pd.DataFrame], pd.Series]
    ) -> pd.DataFrame:
        """Apply one entity-level aggregation function to every IP group.

        The callable must implement the same one-IP aggregation used by a
        detector during inference and return a named pandas Series.
        """

        feature_rows = {}
        for ip_address in self:
            features = aggregation(self[ip_address])
            if not isinstance(features, pd.Series):
                raise TypeError("IP aggregation must return a pandas Series")
            feature_rows[ip_address] = features
        features = pd.DataFrame.from_dict(feature_rows, orient="index")
        features.index.name = self.src_ip_field
        return features


class TimeWindowedIPFlowDataset:
    """Prepare time-windowed flow groups for detector training.

    Attributes
    ----------
    flows : pd.DataFrame
        Loaded flow records sorted by timestamp.
    timestamp_column : str
        Name of the column containing flow timestamps.
    window_size : int, str, or pandas.Timedelta
        Width of each time window. Numeric values are interpreted as seconds.
    src_ip_field : str
        Name of the source-IP column.
    """

    def __init__(
        self,
        data: TableSource,
        *,
        timestamp_column: str,
        window_size: int | str | pd.Timedelta,
        src_ip_field: str = "SRC_IP",
        delimiter: str = ",",
    ) -> None:
        """Load a flow table and configure lazy time-window aggregation.

        Parameters
        ----------
        data : str, pathlib.Path, or pd.DataFrame
            Flow table or path to a CSV file.
        timestamp_column : str
            Name of the column containing flow timestamps.
        window_size : int, str, or pandas.Timedelta
            Positive window width. Numeric values are interpreted as seconds.
        src_ip_field : str, optional
            Name of the source-IP column, by default ``"SRC_IP"``.
        delimiter : str, optional
            Field delimiter used for CSV files, by default ``,`` (comma).
        """
        self.flows = _read_table(data, delimiter)
        self.timestamp_column = timestamp_column
        self.window_size = parse_duration(window_size)
        self.src_ip_field = src_ip_field
        timestamps, time_buckets = assign_time_buckets(
            self.flows,
            timestamp_field=timestamp_column,
            size=self.window_size,
        )
        order = timestamps.argsort(kind="stable")
        self.flows = self.flows.iloc[order].reset_index(drop=True)
        self.flows[timestamp_column] = timestamps.iloc[order].reset_index(drop=True)
        self._time_buckets = time_buckets.iloc[order].reset_index(drop=True)

    def __iter__(self) -> Iterator[tuple[pd.Timestamp, IPFlowDataset]]:
        """Iterate over non-empty time windows and their IP datasets.

        Yields
        ------
        tuple[pd.Timestamp, IPFlowDataset]
            Window start timestamp and the source-IP dataset for that window.
        """

        for window_start, bucket in self.flows.groupby(self._time_buckets, sort=True):
            yield window_start, IPFlowDataset(bucket, src_ip_field=self.src_ip_field)

    def apply(
        self, aggregation: Callable[[pd.DataFrame], pd.Series]
    ) -> pd.DataFrame:
        """Apply one entity-level aggregation to every IP in every window."""

        window_starts = []
        feature_tables = []
        for window_start, ip_dataset in self:
            window_starts.append(window_start)
            feature_tables.append(ip_dataset.apply(aggregation))

        if not feature_tables:
            empty_index = pd.MultiIndex.from_arrays(
                [[], []], names=["window_start", self.src_ip_field]
            )
            return pd.DataFrame(index=empty_index)

        return pd.concat(
            feature_tables,
            keys=window_starts,
            names=["window_start", self.src_ip_field],
        )


__all__ = [
    "IPFlowDataset",
    "ProbabilityClassifier",
    "TimeWindowedIPFlowDataset",
]
