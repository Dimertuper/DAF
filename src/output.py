#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>, Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: output.py
Description: Naming and writing of the DAF output files.
"""

import argparse
import csv
import logging

import pandas as pd

from config import Configurable, Requirement

logger = logging.getLogger("Output")

ANNOTATION_FIELDS = ("group", "_class", "os_family", "os_type", "os_version")


class OutputPaths:
    """Names of the output files derived from the input files.

    Attributes
    ----------
    dataset : str or None
        Path to the flow dataset.
    reannotation : str or None
        Path to the reannotation JSON file.
    """

    def __init__(self, arg: argparse.Namespace) -> None:
        """Initialize the paths from the command-line arguments.

        Parameters
        ----------
        arg : argparse.Namespace
            Command-line arguments with ``dataset`` and ``reannotation``.
        """

        self.dataset = arg.dataset
        self.reannotation = arg.reannotation

    @property
    def dataset_base(self) -> str:
        """Return the dataset path without the ``.csv`` suffix."""

        return self.dataset.split(".csv")[0]

    @property
    def reannotation_base(self) -> str:
        """Return the reannotation path without the ``.json`` suffix."""

        return self.reannotation.split(".json")[0]

    @property
    def annotation_list(self) -> str:
        """Return the path of the IP annotation list CSV."""

        if self.reannotation is not None:
            base = self.dataset_base if self.dataset is not None else self.reannotation_base
            return f"{base}_ip_annotation_list_reannotation.csv"
        return f"{self.dataset_base}_ip_annotation_list.csv"

    @property
    def annotated_dataset(self) -> str:
        """Return the path of the annotated dataset CSV."""

        return f"{self.dataset_base}_annotated.csv"

    @property
    def ip_data(self) -> str:
        """Return the path of the exported IP data JSON."""

        if self.reannotation is None:
            return f"{self.dataset_base}_ip_data.json"
        return f"{self.reannotation_base}_ip_data_updated.json"


class AnnotationListExporter(Configurable):
    """Write the final (and optionally every module's) annotation of each IP to a CSV.

    If ``export_full_annotation`` is enabled, the CSV includes the result of every
    enabled module; otherwise it contains only the final annotation.

    Attributes
    ----------
    config : dict
        Complete DAF configuration.
    delimiter : str
        CSV delimiter.
    """

    REQUIREMENTS = (Requirement("export_full_annotation", bool),)

    def __init__(self, config: dict, delimiter: str) -> None:
        """Check the configuration.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.
        delimiter : str
            CSV delimiter.
        """

        self.check_config(config["daf"], "daf")
        self.config = config
        self.delimiter = delimiter

    def annotation_names(self) -> list:
        """Return the annotation names exported as columns.

        Returns
        -------
        list
            ``final_annotation`` followed by the names of the enabled modules.
        """

        names = ["final_annotation"]
        if not self.config["daf"]["export_full_annotation"]:
            return names
        for key, value in self.config.items():
            if key == "daf" or value["enabled"] is False:
                continue
            if key == "sni_annotator":
                for x in value["fields"]:
                    if isinstance(x, list):
                        names.append(f"sni_annotator_{x[0].split(' ')[-1]}")
                    else:
                        names.append(f"sni_annotator_{x.split(' ')[-1]}")
            else:
                names.append(key)
        return names

    def write(self, ip_addresses: list, filename: str) -> None:
        """Write the annotation list.

        Parameters
        ----------
        ip_addresses : list
            Annotated IP objects.
        filename : str
            Path of the CSV file.
        """

        names = self.annotation_names()
        header = ["ip_address", "possible_NAT"]
        for name in names:
            header += [
                f"{name}_group",
                f"{name}_class",
                f"{name}_os_family",
                f"{name}_os_type",
                f"{name}_os_version",
            ]

        with open(filename, "w", encoding="utf-8") as w:
            writer = csv.writer(w, delimiter=self.delimiter)
            writer.writerow(header)
            for ip in ip_addresses:
                row = [str(ip.ip_addr), bool(ip.multi_device)] + ip.final_annotation.ret_annotation()
                for name in names[1:]:
                    if name in ip.annotations:
                        row += ip.annotations[name].ret_annotation()
                    else:
                        row += [None, None, None, None, None]
                writer.writerow(row)

        logger.info(f"IP annotation saved to file: {filename}")


class DatasetAnnotator:
    """Append the final annotation of the source IP to every flow.

    Attributes
    ----------
    src_ip_field : str
        Name of the source IP column.
    annotation_table : pd.DataFrame
        Final annotation fields indexed by IP address string.
    """

    def __init__(self, ip_addresses: list, src_ip_field: str) -> None:
        """Build the annotation table of the IPs.

        Parameters
        ----------
        ip_addresses : list
            Annotated IP objects.
        src_ip_field : str
            Name of the source IP column.
        """

        self.src_ip_field = src_ip_field
        self.annotation_table = pd.DataFrame(
            [ip.final_annotation.ret_annotation() for ip in ip_addresses],
            index=pd.Index([str(ip.ip_addr) for ip in ip_addresses], name="ip_address"),
            columns=ANNOTATION_FIELDS,
        )

    def annotate(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Attach the final annotations to flows by their source IP.

        Parameters
        ----------
        flows : pd.DataFrame
            Flow records, modified in place.

        Returns
        -------
        pd.DataFrame
            Flows with the appended annotation columns.
        """

        annotations = self.annotation_table.reindex(flows[self.src_ip_field].astype(str))
        annotations.index = flows.index
        flows[list(ANNOTATION_FIELDS)] = annotations
        return flows

    def write(self, flows: pd.DataFrame, filename: str) -> pd.DataFrame:
        """Annotate the flows and save them.

        Parameters
        ----------
        flows : pd.DataFrame
            Flow records.
        filename : str
            Path of the annotated CSV.

        Returns
        -------
        pd.DataFrame
            Annotated flows.
        """

        logger.info("  -- Annotating dataset and saving to file...")
        flows = self.annotate(flows)
        flows.to_csv(filename, index=False)
        logger.info(f"Annotated dataset saved to {filename}")
        return flows


__all__ = ["ANNOTATION_FIELDS", "AnnotationListExporter", "DatasetAnnotator", "OutputPaths"]
