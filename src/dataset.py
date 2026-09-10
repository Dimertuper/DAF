#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: dataset.py
Description: Flow dataset loaded to memory and grouped by source IP address.
"""

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Iterator, Optional, Union

import pandas as pd

logger = logging.getLogger("DAF")


class FlowDataset(Mapping):
    """Flow records of a dataset (or of one window), accessible by source IP address.

    The dataset is a read-only mapping of source IP address strings to the flows of
    that IP, so modules can annotate IP by IP. The per-IP tables are created lazily on
    first access; modules processing all IPs at once use :attr:`flows` directly and
    avoid splitting the flows into thousands of small tables.

    Attributes
    ----------
    flows : pd.DataFrame
        Flow records.
    src_ip_field : str
        Name of the source IP column.
    """

    def __init__(self, flows: pd.DataFrame, src_ip_field: str) -> None:
        """Wrap flow records.

        Parameters
        ----------
        flows : pd.DataFrame
            Flow records.
        src_ip_field : str
            Name of the source IP column.
        """

        self.flows = flows
        self.src_ip_field = src_ip_field
        self._groups = None
        self._keys = None

    @classmethod
    def read_csv(cls, path: Union[str, Path], delimiter: str, src_ip_field: str) -> "FlowDataset":
        """Load the complete CSV dataset to memory.

        Parameters
        ----------
        path : str or pathlib.Path
            Path to the CSV dataset.
        delimiter : str
            CSV delimiter.
        src_ip_field : str
            Name of the source IP column.

        Returns
        -------
        FlowDataset
            Loaded dataset.
        """

        logger.info("  -- loading complete dataset to memory ... ")
        return cls(pd.read_csv(path, delimiter=delimiter, low_memory=False), src_ip_field)

    @classmethod
    def coerce(cls, flows_by_ip: Optional[Mapping], src_ip_field: str) -> "FlowDataset":
        """Return flows passed to a module as a :class:`FlowDataset`.

        Parameters
        ----------
        flows_by_ip : FlowDataset, Mapping or None
            Dataset, or flow DataFrames keyed by source IP address string.
        src_ip_field : str
            Name of the source IP column.

        Returns
        -------
        FlowDataset
            The dataset itself, or a dataset built from the per-IP tables.
        """

        if isinstance(flows_by_ip, FlowDataset):
            return flows_by_ip
        tables = [flows for flows in (flows_by_ip or {}).values() if not flows.empty]
        if not tables:
            return cls(pd.DataFrame(columns=[src_ip_field]), src_ip_field)
        return cls(pd.concat(tables), src_ip_field)

    @property
    def groups(self) -> dict:
        """Return the flows split by source IP, created on first access.

        Returns
        -------
        dict
            Flow DataFrames keyed by source IP address string.
        """

        if self._groups is None:
            self._groups = {str(ip): group for ip, group in self.flows.groupby(self.src_ip_field)}
        return self._groups

    def ip_keys(self) -> set:
        """Return the source IP address strings without splitting the flows.

        Returns
        -------
        set
            Source IP addresses.
        """

        if self._keys is None:
            if self._groups is not None:
                self._keys = set(self._groups)
            else:
                self._keys = set(self.flows[self.src_ip_field].dropna().astype(str).unique())
        return self._keys

    def __getitem__(self, ip: str) -> pd.DataFrame:
        """Return the flows of one source IP address string."""

        return self.groups[ip]

    def __contains__(self, ip: object) -> bool:
        """Return whether a source IP address string has flows."""

        return ip in self.ip_keys()

    def __iter__(self) -> Iterator[str]:
        """Iterate over the source IP address strings."""

        return iter(self.groups)

    def __len__(self) -> int:
        """Return the number of source IP addresses."""

        return len(self.ip_keys())

    def flows_by_ip(self, keys: Optional[set] = None) -> "FlowDataset":
        """Return the dataset restricted to some source IP addresses.

        Parameters
        ----------
        keys : set, optional
            If given, only flows whose source IP string is in ``keys`` are kept.

        Returns
        -------
        FlowDataset
            The dataset itself, or a new dataset with the selected flows.
        """

        if keys is None:
            return self
        mask = self.flows[self.src_ip_field].astype(str).isin(keys)
        return FlowDataset(self.flows[mask], self.src_ip_field)


__all__ = ["FlowDataset"]
