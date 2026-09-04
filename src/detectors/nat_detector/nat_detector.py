#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: nat_detector.py
Description: NAT detector modul used to detect NAT devices.
"""

import logging

from config import Requirement
from core import DAFModule

logger = logging.getLogger("NAT detector")


class NATDetector(DAFModule):
    """Detect NAT devices by the number of unique TTL values and source ports.

    An IP is flagged as a possible multi-device if its flows contain at least
    ``min_unique_ttl`` distinct TTL counts and ``min_unique_src_ports`` distinct
    source ports. Zero values are ignored.
    """

    name = "nat_detector"
    description = "NAT detection"
    REQUIREMENTS = (
        Requirement("field", str),
        Requirement("min_unique_ttl", int, default=5, minimum=0),
        Requirement("min_unique_src_ports", int, default=500, minimum=0),
    )
    DAF_REQUIREMENTS = (Requirement("src_port_field", str),)

    def before_run(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Check that the TTL and source port columns are present.

        Parameters
        ----------
        ip_addresses : list
            IP objects that will be annotated.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.

        Raises
        ------
        RuntimeError
            If one of the columns is missing.
        """

        _, first_value = next(iter(flows_by_ip.items()))
        if (
            self.config["field"] not in first_value.columns
            or self.daf_config["src_port_field"] not in first_value.columns
        ):
            logger.error(
                f"Field {self.config['field']} or {self.daf_config['src_port_field']} not found in DataFrame"
            )
            raise RuntimeError(
                f"NAT detector field {self.config['field']} or {self.daf_config['src_port_field']} not found in DataFrame"
            )

    def annotate_ip(self, ip, flows=None) -> None:
        """Flag one IP address as a possible NAT.

        Parameters
        ----------
        ip : IP
            IP object to check.
        flows : pd.DataFrame, optional
            Flows of the IP.
        """

        if flows is None or flows.empty:
            return

        ttl_values = flows[self.config["field"]]
        src_ports = flows[self.daf_config["src_port_field"]]
        ttl_values = ttl_values[ttl_values != 0]
        src_ports = src_ports[src_ports != 0]

        ttl_counts = ttl_values.value_counts()
        unique_ttl_values = ttl_counts.nunique()
        unique_src_ports = src_ports.nunique()

        if (
            unique_ttl_values < self.config["min_unique_ttl"]
            or unique_src_ports < self.config["min_unique_src_ports"]
        ):
            return

        ip.multi_device.append(
            ["NAT_detector", [ttl_counts.to_dict(), src_ports.value_counts().to_dict()]]
        )
