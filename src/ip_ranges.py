#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: ip_ranges.py
Description: Selection of the IP addresses to annotate from flows, filtered by protected IP ranges.
"""

import csv
import ipaddress
import logging
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd

from config import Configurable, Requirement
from ip import IP, IPCollection

logger = logging.getLogger("load_ip_ranges")


def _check_ip_ranges(value: str) -> Optional[str]:
    """Return an error message if ``ip_ranges`` is neither ``ALL`` nor an existing file."""

    if value == "ALL" or Path(value).is_file():
        return None
    return f"File {value} does not exist"


class IPSelector(Configurable):
    """Select the IP addresses to annotate from flows.

    Source (and, if ``dst_ip_field`` is set, destination) IP addresses of the flows are
    selected. If ``ip_ranges`` is a CSV file, only addresses listed in it or belonging to
    one of its networks are selected; ``ALL`` selects every address.

    Attributes
    ----------
    src_ip_field : str
        Name of the source IP column.
    dst_ip_field : str or None
        Name of the destination IP column.
    protected_networks : list or None
        Networks of the IP range file, None for ``ALL``.
    protected_ip_addrs : list or None
        Addresses of the IP range file, None for ``ALL``.
    """

    REQUIREMENTS = (
        Requirement("ip_ranges", str, check=_check_ip_ranges),
        Requirement("src_ip_field", str),
        Requirement("dst_ip_field", str, default=None),
    )

    def __init__(self, config: dict) -> None:
        """Check the configuration and load the IP ranges.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.
        """

        daf_config = self.check_config(config["daf"], "daf")
        self.src_ip_field = daf_config["src_ip_field"]
        self.dst_ip_field = daf_config["dst_ip_field"]
        self.protected_networks, self.protected_ip_addrs = self.load_ip_ranges(daf_config["ip_ranges"])

    @staticmethod
    def load_ip_ranges(filename: str) -> Tuple[Optional[list], Optional[list]]:
        """Load IP addresses and networks from a CSV file.

        Parameters
        ----------
        filename : str
            Path to the CSV file with ``ip,type`` rows (``addr`` or ``network``), or
            ``ALL``.

        Returns
        -------
        tuple
            Protected networks and protected IP addresses, both None for ``ALL``.
        """

        if filename == "ALL":
            return None, None
        protected_networks = []
        protected_ip_addrs = []
        path = Path(filename)

        if not path.exists():
            logger.error(f"Config parameter ip_ranges: File {filename} does not exist")
            raise FileNotFoundError(f"Config parameter ip_ranges: File {filename} does not exist")

        with path.open("r") as f:
            reader = csv.reader(f, delimiter=",")
            for row in reader:
                if not row or row[0] == "ip":
                    continue
                if row[1] == "addr":
                    protected_ip_addrs.append(row[0])
                elif row[1] == "network":
                    protected_networks.append(ipaddress.ip_network(row[0]))
                else:
                    print(
                        f"  -- warning: loading unknown type: {row[1]}, IP address or network: {row[0]} is ignored"
                    )

        return protected_networks, protected_ip_addrs

    def select(self, flows: pd.DataFrame) -> List[IP]:
        """Create IP objects of the protected IP addresses of the flows.

        Parameters
        ----------
        flows : pd.DataFrame
            Flow records.

        Returns
        -------
        list
            New IP objects, one for every selected address, also if it is both a
            source and a destination.

        Raises
        ------
        KeyError
            If an IP column is missing in the flows.
        """

        if self.src_ip_field not in flows.columns:
            logger.error("Column 'src_ip_field' not found in the dataframe")
            raise KeyError("Column 'src_ip_field' not found in the dataframe")
        if self.dst_ip_field is not None and self.dst_ip_field not in flows.columns:
            logger.error("Column 'dst_ip_field' not found in the dataframe")
            raise KeyError("Column 'dst_ip_field' not found in the dataframe")

        ips = flows[self.src_ip_field].unique().tolist()
        if self.dst_ip_field is not None:
            ips += flows[self.dst_ip_field].unique().tolist()

        ip_addresses = IPCollection()
        for ip in ips:
            if self.protected_networks is None and self.protected_ip_addrs is None:
                ip_addresses.add(IP(ip))
                continue
            if ip in self.protected_ip_addrs:
                ip_addresses.add(IP(ip))
                continue
            ip_addr = ipaddress.ip_address(ip)
            for net in self.protected_networks:
                if ip_addr in net:
                    ip_addresses.add(IP(ip))
                    break

        return ip_addresses.to_list()


__all__ = ["IPSelector"]
