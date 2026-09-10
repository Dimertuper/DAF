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
from dataset import FlowDataset

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
    DAF_REQUIREMENTS = (Requirement("src_port_field", str), Requirement("src_ip_field", str))

    def required_columns(self) -> tuple:
        """Return the TTL and source port columns.

        Returns
        -------
        tuple
            Names of the TTL and source port columns.
        """

        return (self.config["field"], self.daf_config["src_port_field"])

    def detect_all(self, ip_addresses: list, flows_by_ip) -> dict:
        """Count unique TTL values and source ports of all IP addresses at once.

        Parameters
        ----------
        ip_addresses : list
            Target IP objects.
        flows_by_ip : Mapping
            Flows keyed by source IP address string.

        Returns
        -------
        dict
            Results of :meth:`detect` keyed by IP address string.
        """

        dataset = FlowDataset.coerce(flows_by_ip, self.daf_config["src_ip_field"])
        flows = dataset.flows
        src = dataset.src_ip_field
        ttl_field = self.config["field"]
        port_field = self.daf_config["src_port_field"]

        ttl = flows.loc[flows[ttl_field] != 0, [src, ttl_field]]
        ttl_counts = ttl.groupby([src, ttl_field]).size()
        unique_ttl = ttl_counts.groupby(level=0).nunique()
        ports = flows.loc[flows[port_field] != 0, [src, port_field]]
        unique_ports = ports.groupby(src)[port_field].nunique()
        unique_ttl = {str(key): int(value) for key, value in unique_ttl.items()}
        unique_ports = {str(key): int(value) for key, value in unique_ports.items()}

        results = {}
        for ip in ip_addresses:
            key = str(ip.ip_addr)
            if key not in dataset:
                continue
            unique_ttl_values = unique_ttl.get(key, 0)
            unique_src_ports = unique_ports.get(key, 0)
            results[key] = {
                "detected": unique_ttl_values >= self.config["min_unique_ttl"]
                and unique_src_ports >= self.config["min_unique_src_ports"],
                "unique_ttl_values": unique_ttl_values,
                "unique_src_ports": unique_src_ports,
            }
        return results

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
