#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: hand_annotator.py
Description: Hand annotator module used to annotate IP addresses with hand-crafted annotations.
"""

import csv
import ipaddress
import logging
from pathlib import Path
from typing import Optional

from config import Requirement
from core import DAFModule
from ip import Annotation

logger = logging.getLogger("Hand Annotator")


class HandAnnotationRules:
    """Hand annotation rules of single IP addresses and IP networks.

    Rules are read from a CSV file with the columns ``ip_address, group, class,
    os-family, os-type, os-version``. The address can be a single IP, a network in CIDR
    notation, or a range of the last octet such as ``10.0.0.{1-10}``.

    Attributes
    ----------
    devices : dict
        Annotations of single IP addresses.
    networks : dict
        Annotations of IP networks.
    """

    def __init__(self, path: Path) -> None:
        """Load the rules.

        Parameters
        ----------
        path : pathlib.Path
            Path to the CSV file with the rules.
        """

        self.devices, self.networks = self.load(path)

    def lookup(self, ip_addr) -> Optional[tuple]:
        """Return the labels of the rule matching an IP address.

        Parameters
        ----------
        ip_addr : ipaddress.IPv4Address or ipaddress.IPv6Address
            IP address.

        Returns
        -------
        tuple or None
            ``(group, class, os_family, os_type, os_version)`` or None.
        """

        if str(ip_addr) in self.devices:
            return self.devices[ip_addr]
        for network, annotation in self.networks.items():
            if ip_addr in network:
                return annotation
        return None

    @staticmethod
    def load(path: Path) -> tuple:
        """Read the rules from a CSV file.

        Parameters
        ----------
        path : pathlib.Path
            Path to the CSV file with the rules.

        Returns
        -------
        tuple
            Annotations of single IP addresses and of IP networks.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        """
        device_hand_annotation = {}
        network_hand_annotation = {}

        if not path.exists():
            logger.error(f"Annotation file {path} does not exist")
            raise FileNotFoundError(f"Hand Annotator, path to database: {path} does not exist")

        with path.open(mode="r") as f:
            reader = csv.reader(f, delimiter=",")
            for row in reader:
                if row[0] == "ip_address":
                    continue
                if "/" in row[0]:
                    network_hand_annotation[ipaddress.ip_network(row[0])] = (
                        row[1],
                        row[2],
                        row[3],
                        row[4],
                        row[5],
                    )
                elif "{" in row[0]:
                    prefix = row[0].split("{")[0]
                    start_stop = row[0].split("{")[1].split("}")[0].split("-")
                    for i in range(int(start_stop[0]), int(start_stop[1])):
                        device_hand_annotation[ipaddress.ip_address(f"{prefix}{i}")] = (
                            row[1],
                            row[2],
                            row[3],
                            row[4],
                            row[5],
                        )
                else:
                    device_hand_annotation[ipaddress.ip_address(row[0])] = (
                        row[1],
                        row[2],
                        row[3],
                        row[4],
                        row[5],
                    )

        return device_hand_annotation, network_hand_annotation


class HandAnnotator(DAFModule):
    """Annotate IP addresses with hand-crafted annotations from a CSV database.

    Hand annotations override the merged annotation of the other modules, see
    :meth:`ip.IP.perform_annotation`.

    Attributes
    ----------
    rules : HandAnnotationRules
        Loaded rules.
    """

    name = "hand_annotator"
    description = "hand annotation"
    REQUIREMENTS = (Requirement("db", str, path="file"),)

    def setup(self) -> None:
        """Load the hand annotation rules from ``db``."""

        self.rules = HandAnnotationRules(Path(self.config["db"]))

    def annotate_ip(self, ip, flows=None) -> None:
        """Annotate one IP address with the matching hand annotation rule.

        Parameters
        ----------
        ip : IP
            IP object to annotate.
        flows : pd.DataFrame, optional
            Not used.
        """

        labels = self.rules.lookup(ip.ip_addr)
        if labels is not None:
            ip.add_annotation("hand_annotator", Annotation(*labels))
