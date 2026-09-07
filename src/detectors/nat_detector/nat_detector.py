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
from core import Detector

logger = logging.getLogger("NAT detector")


class NATDetector(Detector):
    """Detect NAT devices by the number of unique TTL values and source ports.

    An IP is flagged as a possible multi-device if its flows contain at least
    ``min_unique_ttl`` distinct TTL counts and ``min_unique_src_ports`` distinct
    source ports. Zero values are ignored.
    """

    name = "nat_detector"
    description = "NAT detection"
    evidence_label = "NAT_detector"
    REQUIREMENTS = (
        Requirement("field", str),
        Requirement("min_unique_ttl", int, default=5, minimum=0),
        Requirement("min_unique_src_ports", int, default=500, minimum=0),
    )
    DAF_REQUIREMENTS = (Requirement("src_port_field", str),)

    def required_columns(self) -> tuple:
        """Return the TTL and source port columns.

        Returns
        -------
        tuple
            Names of the TTL and source port columns.
        """

        return (self.config["field"], self.daf_config["src_port_field"])

    def detect(self, ip, flows) -> dict:
        """Count unique TTL values and source ports of one IP address.

        Parameters
        ----------
        ip : IP
            IP object to check.
        flows : pd.DataFrame
            Flows of the IP.

        Returns
        -------
        dict
            ``detected`` decision with the counted values.
        """

        ttl_values = flows[self.config["field"]]
        src_ports = flows[self.daf_config["src_port_field"]]
        ttl_values = ttl_values[ttl_values != 0]
        src_ports = src_ports[src_ports != 0]

        unique_ttl_values = int(ttl_values.value_counts().nunique())
        unique_src_ports = int(src_ports.nunique())

        return {
            "detected": unique_ttl_values >= self.config["min_unique_ttl"]
            and unique_src_ports >= self.config["min_unique_src_ports"],
            "unique_ttl_values": unique_ttl_values,
            "unique_src_ports": unique_src_ports,
        }
