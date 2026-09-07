#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: sni_annotator.py
Description: SNI annotator module used to annotate IP addresses with SNI-based metadata.
"""

import csv
import logging
from collections import Counter
from pathlib import Path

import pandas as pd

from config import Requirement
from core import FlowAnnotator
from ip import Annotation

logger = logging.getLogger("SNI Annotator")


class SNIDatabase:
    """SNI Annotator class.

    Attributes
    ----------
    os_db : dict[dict[str, str]]
        Dictionary with SNI as key and OS family and group as values.
    """

    def __init__(self, db_path: str) -> None:
        """SNI Annotator constructor.

        Parameters
        ----------
        db_path : str
            Path to database file.

        Raises
        ------
        FileNotFoundError
            If the database file does not exist.
        ValueError
            If the database could not be loaded.
        """
        self.os_db = None

        db_path = Path(db_path)
        if not db_path.exists():
            logger.error(f"Database file {db_path} does not exist")
            raise FileNotFoundError("SNI_annotator:: Path to db_file does not exist")

        with db_path.open("r", encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            self.os_db = {}

            header = next(csv_reader, None)
            if header != ["url", "uri", "os_family"]:
                logger.error(
                    f"Invalid database header: {header}, expected ['url', 'uri', 'os_family']"
                )
                raise ValueError("SNI_annotator:: Invalid database header")

            for i, row in enumerate(csv_reader):
                if len(row) < 3:
                    logger.warning(f"Skipping malformed row {i}: {row}")
                    continue
                self.os_db[row[0]] = {"path": row[1], "os": row[2]}

        if not self.os_db:
            logger.error("Unable to load database or database is empty")
            raise ValueError("SNI_annotator:: Unable to load database")

    def get_os(self, data: list) -> list:
        """Get OS family and group for given SNI.
        TODO: Upgrade strip, add class group...

        Parameters
        ----------
        data : list
            List with host and uri to classify.

        Returns
        -------
        list
            List with OS family and group.
        """

        os_family = os_type = group = _class = None
        host, uri = data

        host = host.strip()
        os = self.os_db.get(host, None)

        # Check if None or specific path necessary for classification
        if os is None or (os["path"] != "*" and (uri is None or os["path"] not in uri)):
            return [None, None, None, None]

        os = os["os"]

        if os == "windows":
            os_family = "windows"
            os_type = "windows"
        if os == "macos":
            os_family = "macos"
            os_type = "macos"
            group = "end-device"
        if os == "android":
            os_family = "android"
            os_type = "android"
            group = "end-device"
            _class = "mobile"
        if os in ["ubuntu", "mint"]:
            os_family = "linux"
            os_type = "ubuntu"
        if os == "debian":
            os_family = "linux"
            os_type = "debian"
        if os == "fedora":
            os_family = "linux"
            os_type = "fedora"
        if os == "opensuse":
            os_family = "linux"
            os_type = "opensuse"
        if os in ["archlinux", "manjaro"]:
            os_family = "linux"
            os_type = "arch linux"

        return [os_family, os_type, group, _class]


class SNIAnnotator(FlowAnnotator):
    """Annotate IP addresses by server names (TLS/QUIC SNI, HTTP host, DNS) in their flows.

    Every configured field produces its own annotation named ``sni_annotator_<field>``.

    Attributes
    ----------
    sni_db : SNIDatabase
        Database mapping server names to operating systems.
    fields : list
        ``[host_field, uri_field]`` pairs present in the dataset.
    """

    name = "sni_annotator"
    description = "SNI Annotation"
    REQUIREMENTS = (Requirement("db_file", str), Requirement("fields", list))
    DAF_REQUIREMENTS = (Requirement("min_annotation_count", int),)

    @staticmethod
    def most_common(lst: list) -> str:
        """Function used to get most common element from list.

        Parameters
        ----------
        lst : list
            List of elements to get most common from.

        Returns
        -------
        str
            Most common element from list.
        """

        if len(lst) == 0:
            return None
        counter = Counter(lst).most_common()

        return counter[0][0]

    @staticmethod
    def server_names(ip_data: pd.DataFrame, host_field: str, uri_field) -> list:
        """Function used to get [host,uri] pairs from flows of one IP address.

        Parameters
        ----------
        ip_data : pd.DataFrame
            Flows of the IP address.
        host_field : str
            Field in DataFrame with hostnames.
        uri_field : str
            Field in DataFrame with URIs.

        Returns
        -------
        list
            List of [host,uri] pairs for given IP address.
        """

        if ip_data is None or len(ip_data) == 0:
            return None

        if uri_field is not None:
            snis = (
                ip_data[ip_data[host_field].notna()][[host_field, uri_field]]
                .replace({uri_field: {"": None}})
                .drop_duplicates()
                .values.tolist()
            )
        else:
            snis = ip_data[host_field].dropna().drop_duplicates().tolist()
            snis = [[value, None] for value in ip_data[host_field].dropna().drop_duplicates()]

        if len(snis) > 0:
            return snis

        return None

    @staticmethod
    def annotation_from_server_names(
        data: list, sin_database: SNIDatabase, min_annotation_count: int
    ) -> list:
        """Function used to get annotation based on TLS SNI.                            ----------------- TODO

        Parameters
        ----------
        host_names : list
            List of HTTP hostnames to get annotation for.
        annotator : sni_annotator.SNI
            Annotator used to get annotation.
        min_annotation_count : int
            Minimal number of annotated samples, needed to assign label.

        Returns
        -------
        list
            List of annotations for given HTTP hostnames.
        """

        os_family = []
        os_type = []
        groups = []
        classes = []
        multi_flag = []

        for hosturi in data:
            t_family, t_type, t_group, t_class = sin_database.get_os(hosturi)
            if t_family is not None:
                os_family.append(t_family)
            if t_type is not None:
                os_type.append(t_type)
            if t_group is not None:
                groups.append(t_group)
            if t_class is not None:
                classes.append(t_class)

        if len(set(os_family)) > 1:
            multi_flag.append(list(set(os_family)))

        if len(os_family) > 0 and Counter(os_family).most_common()[0][1] < min_annotation_count:
            return [None, None, None, None, None, multi_flag]

        return [
            SNIAnnotator.most_common(groups),
            SNIAnnotator.most_common(classes),
            SNIAnnotator.most_common(os_family),
            SNIAnnotator.most_common(os_type),
            None,
            multi_flag,
        ]

    @staticmethod
    def fields_from_config(local_config: dict, first_value: pd.DataFrame) -> list:
        """Function used to get fields from configuration file.

        Parameters
        ----------
        local_config : dict
            Configuration of annotator.
        first_value : pd.DataFrame
            DataFrame for first ip, used to check fields.

        Returns
        -------
        list
            _description_
        """

        fields = []
        for field in local_config["fields"]:
            if isinstance(field, list) and len(field) == 2:
                host, uri = field
            else:
                host = field
                uri = None

            if host not in first_value.columns:
                logger.error(f"Field {host} not found in dataframe, skipping")
                continue
            if uri is not None and uri not in first_value.columns:
                logger.error(f"Field {uri} not found in dataframe, setting to None")
                uri = None

            fields.append([host, uri])

        return fields

    def setup(self) -> None:
        """Load the SNI database."""

        self.sni_db = SNIDatabase(self.config["db_file"])
        self.fields = []

    def validate_flows(self, flows: pd.DataFrame) -> None:
        """Select the configured fields present in the flows.

        Missing fields are skipped, a missing URI field is replaced by None.

        Parameters
        ----------
        flows : pd.DataFrame
            Flows of one IP address, used as a sample of the dataset schema.
        """

        if len(self.config["fields"]) == 0:
            logger.error("No fields in configuration file, nothing to annotate")
            self.fields = []
            return
        self.fields = self.fields_from_config(self.config, flows)

    def annotate_ip(self, ip, flows) -> None:
        """Annotate one IP address by the server names found in each configured field.

        Parameters
        ----------
        ip : IP
            IP object to annotate.
        flows : pd.DataFrame
            Flows of the IP.
        """

        for host, uri in self.fields:
            data = self.server_names(flows, host, uri)
            if data is not None:
                ip.add_data(f"sni_annotator_{host.split(' ')[-1]}", data)
                (
                    group,
                    _class,
                    os_family,
                    os_type,
                    os_version,
                    multi_flag,
                ) = self.annotation_from_server_names(
                    data,
                    self.sni_db,
                    self.daf_config["min_annotation_count"],
                )

                if len(multi_flag) > 0:
                    ip.multi_device.append([host.split(" ")[-1], multi_flag])

                ip.add_annotation(
                    f"sni_annotator_{host.split(' ')[-1]}",
                    Annotation(group, _class, os_family, os_type, os_version),
                )
