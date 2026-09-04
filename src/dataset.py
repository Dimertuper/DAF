#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: dataset.py
Description: Flow dataset loaded to memory and grouped by source IP address.
"""

import logging
from pathlib import Path
from typing import Optional, Union

import pandas as pd

logger = logging.getLogger("DAF")


class FlowDataset:
    """Flow records and their grouping by source IP address.

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

    def flows_by_ip(self, keys: Optional[set] = None) -> dict:
        """Group flows by their source IP address.

        Parameters
        ----------
        keys : set, optional
            If given, only groups whose IP string is in ``keys`` are returned.

        Returns
        -------
        dict
            Flow DataFrames keyed by source IP address string.
        """

        grouped = {}
        for ip, group in self.flows.groupby(self.src_ip_field):
            if keys is None or str(ip) in keys:
                grouped[str(ip)] = group
        return grouped


__all__ = ["FlowDataset"]
