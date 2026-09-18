#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: output.py
Description: Functions for exporting IP annotation lists and annotating datasets.
"""

import argparse
import csv
import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger("Output")


def export_ip_annotation_list(ip_addresses: list, arg: argparse.Namespace, config: dict) -> None:
    """Export IP annotation list to a CSV file.

    Dataset and reannotation runs retain their existing filename conventions. A
    standalone annotator input uses ``arg.output_source``. If
    ``export_full_annotation`` is enabled, the CSV includes every enabled annotator's
    result; otherwise it contains only the final voted annotation.

    Parameters
    ----------
    ip_addresses : list
        A list of IP addresses to export.
    arg : argparse.Namespace
        Command-line arguments and, for standalone input, ``output_source``.
    config : dict
        Configuration dictionary.

    Returns
    -------
    None
        This function does not return anything.
    """
    if arg.reannotation is not None:
        if arg.dataset is not None:
            filename = f"{arg.dataset.split('.csv')[0]}_ip_annotation_list_reannotation.csv"
        else:
            filename = f"{arg.reannotation.split('.json')[0]}_ip_annotation_list_reannotation.csv"
    elif arg.dataset is not None:
        filename = f"{arg.dataset.split('.csv')[0]}_ip_annotation_list.csv"
    else:
        filename = f"{Path(arg.output_source).with_suffix('')}_ip_annotation_list.csv"

    with open(filename, "w", encoding="utf-8") as w:
        tmp = ["final_annotation"]
        if config["daf"]["export_full_annotation"]:
            for key, value in config.items():
                if key == "daf" or value["enabled"] is False:
                    continue
                if key == "sni_annotator":
                    for x in value["fields"]:
                        if isinstance(x, list):
                            tmp.append(f"sni_annotator_{x[0].split(' ')[-1]}")
                        else:
                            tmp.append(f"sni_annotator_{x.split(' ')[-1]}")
                else:
                    tmp.append(key)

        header = ["ip_address", "possible_NAT"]
        for x in tmp:
            header += [
                f"{x}_group",
                f"{x}_class",
                f"{x}_os_family",
                f"{x}_os_type",
                f"{x}_os_version",
            ]

        writer = csv.writer(w, delimiter=arg.d)
        writer.writerow(header)

        for ip in ip_addresses:
            nat = False
            if len(ip.multi_device) > 0:
                nat = True
            row = [str(ip.ip_addr)] + [nat] + ip.final_annotation.ret_annotation()
            if config["daf"]["export_full_annotation"]:
                for annotator in tmp:
                    if annotator == "final_annotation":
                        continue
                    if annotator in ip.annotations:
                        row += ip.annotations[annotator].ret_annotation()
                    else:
                        row += [None, None, None, None, None]
            writer.writerow(row)

    logger.info(f"IP annotation saved to file: {filename}")


def annotate_dataset(
    flows: pd.DataFrame, ip_addresses: list, arg: argparse.Namespace, config: dict
) -> pd.DataFrame:
    """TODO: Add docstring"""

    logger.info("  -- Annotating dataset and saving to file...")

    annotation_map = {}

    # Fill the dictionary with IPs and their annotations
    for ip in ip_addresses:
        (
            group,
            _class,
            os_family,
            os_type,
            os_version,
        ) = ip.final_annotation.ret_annotation()
        annotation_map[str(ip.ip_addr)] = {
            "group": group,
            "_class": _class,
            "os_family": os_family,
            "os_type": os_type,
            "os_version": os_version,
        }

    # Vectorized annotation using the mapping
    src_ip_field = config["daf"]["src_ip_field"]
    flows["group"] = flows[src_ip_field].map(lambda ip: annotation_map.get(ip, {}).get("group"))
    flows["_class"] = flows[src_ip_field].map(lambda ip: annotation_map.get(ip, {}).get("_class"))
    flows["os_family"] = flows[src_ip_field].map(
        lambda ip: annotation_map.get(ip, {}).get("os_family")
    )
    flows["os_type"] = flows[src_ip_field].map(lambda ip: annotation_map.get(ip, {}).get("os_type"))
    flows["os_version"] = flows[src_ip_field].map(
        lambda ip: annotation_map.get(ip, {}).get("os_version")
    )

    # Export dataset to CSV
    output_file = f"{arg.dataset.split('.csv')[0]}_annotated.csv"
    flows.to_csv(output_file, index=False)

    logger.info(f"Annotated dataset saved to {output_file}")

    return flows
