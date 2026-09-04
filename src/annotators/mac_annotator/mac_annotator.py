#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: mac_annotator.py
Description: Provides MAC address-based device annotation using OUI database.
"""

import csv
import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from config import Requirement
from core import DAFModule
from ip import Annotation

logger = logging.getLogger("MAC Annotator")


class OUIDatabase:
    """Database mapping MAC address OUIs to vendors and operating system families.

    Attributes
    ----------
    os_db : dict
        OUI mapped to ``{"vendor": ..., "os": ...}``.
    """

    def __init__(self, db_file: str) -> None:
        """Load the database.

        Parameters
        ----------
        db_file : str
            Path to the CSV database with ``OUI, vendor, OS family`` rows.

        Raises
        ------
        FileNotFoundError
            If the database file does not exist.
        ValueError
            If the database cannot be loaded.
        """

        self.os_db = None

        db_path = Path(db_file)
        if not db_path.exists():
            logger.error(f"MAC_annotator:: database file {db_path} does not exist")
            raise FileNotFoundError(
                "MAC_annotator:: Path to db_file does not exist: {}".format(db_path)
            )

        with db_path.open("r", encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            self.os_db = {row[0]: {"vendor": row[1], "os": row[2]} for row in csv_reader}

        if self.os_db is None:
            logger.error("Unable to load database")
            raise ValueError("MAC_annotator:: Unable to load database")

    def get_os(self, oui: str) -> Optional[str]:
        """Return the OS family of an OUI.

        Parameters
        ----------
        oui : str
            OUI to get OS for.

        Returns
        -------
        str or None
            OS family for given OUI.
        """

        if oui in self.os_db:
            return self.os_db[oui]["os"]

        return None

    def annotation_for(self, mac: str) -> list:
        """Return the annotation fields of a MAC address.

        Parameters
        ----------
        mac : str
            MAC address.

        Returns
        -------
        list
            Group, class and OS family.
        """

        group = _class = family = None

        if len(mac) > 8:
            mac = mac[:8]

        family = self.get_os(mac)

        if family == "android":
            group = "end-device"
            _class = "mobile"

        if family == "macos":
            group = "end-device"

        return [group, _class, family]


class MACAnnotator(DAFModule):
    """Annotate IP addresses by the vendor (OUI) of the MAC addresses in their flows.

    If an IP uses more than one MAC address, it is flagged as a possible multi-device.

    Attributes
    ----------
    oui_database : OUIDatabase
        Database mapping OUIs to vendors and operating systems.
    """

    name = "mac_annotator"
    description = "MAC annotation"
    REQUIREMENTS = (
        Requirement("db_file", str),
        Requirement("src_mac_field", str),
        Requirement("dst_mac_field", str, required=False),
    )
    DAF_REQUIREMENTS = (Requirement("dst_ip_field", str, default=None),)

    @staticmethod
    def collect_macs(ip, flows_by_ip: Optional[dict], field: str) -> Optional[list]:
        """Return the distinct MAC addresses of an IP.

        Parameters
        ----------
        ip : str
            Key of the IP in ``flows_by_ip``.
        flows_by_ip : dict or None
            Flow DataFrames keyed by IP address.
        field : str
            MAC address column.

        Returns
        -------
        list or None
            MAC addresses, or None if there are none.
        """

        if flows_by_ip is None:
            return None

        ip_data = flows_by_ip.get(ip, None)
        if ip_data is not None:
            macs = ip_data[field].dropna().drop_duplicates().tolist()
            if len(macs) > 0:
                return macs

        return None

    def setup(self) -> None:
        """Load the OUI database."""

        self.oui_database = OUIDatabase(self.config["db_file"])

    def before_run(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Check the MAC column and group flows by destination IP if configured.

        Parameters
        ----------
        ip_addresses : list
            IP objects that will be annotated.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.

        Raises
        ------
        ValueError
            If the source MAC column is missing.
        """

        self._flows_by_ip = flows_by_ip
        _, first_value = next(iter(flows_by_ip.items()))
        if self.config["src_mac_field"] not in first_value.columns:
            logger.error(f"Column {self.config['src_mac_field']} not found in the dataframe")
            raise ValueError(
                f"MAC Annotator:: Column {self.config['src_mac_field']} not found in the dataframe"
            )

        self._dst_grouped_dfs = None
        if self.daf_config["dst_ip_field"] is not None:
            self._dst_grouped_dfs = {
                k: v
                for k, v in pd.concat(flows_by_ip.values()).groupby(self.daf_config["dst_ip_field"])
            }

    def annotate_ip(self, ip, flows=None) -> None:
        """Annotate one IP address by its MAC address.

        Parameters
        ----------
        ip : IP
            IP object to annotate.
        flows : pd.DataFrame, optional
            Flows of the IP.
        """

        macs = self.collect_macs(str(ip.ip_addr), self._flows_by_ip, self.config["src_mac_field"])
        if self._dst_grouped_dfs is not None:
            if "dst_mac_field" not in self.config:
                logger.warning(
                    "MAC Annotator:: 'dst_ip_field' set but 'dst_mac_field' is missing in mac_annotator configuration. Skipping MAC annotation of dst IPs."
                )
            dst_macs = self.collect_macs(str(ip.ip_addr), self._dst_grouped_dfs, self.config["dst_mac_field"])
            if dst_macs is not None:
                macs += dst_macs

        if macs is not None:
            if len(macs) > 1:
                ip.multi_device.append(["MAC", macs])
                return
            ip.add_data("mac_annotator", macs)

            group, _class, os_family = self.oui_database.annotation_for(macs[0])
            ip.add_annotation("mac_annotator", Annotation(group, _class, os_family, None, None))
