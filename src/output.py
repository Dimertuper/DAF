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

import pandas as pd

logger = logging.getLogger("Output")

ANNOTATION_FIELDS = ("group", "_class", "os_family", "os_type", "os_version")


def _create_annotation_table(ip_addresses: list) -> pd.DataFrame:
    """Create an IP-indexed table of final annotations."""

    return pd.DataFrame(
        [ip.final_annotation.ret_annotation() for ip in ip_addresses],
        index=pd.Index([str(ip.ip_addr) for ip in ip_addresses], name="ip_address"),
        columns=ANNOTATION_FIELDS,
    )


def _annotate_flows(
    flows: pd.DataFrame,
    annotation_table: pd.DataFrame,
    src_ip_field: str,
) -> pd.DataFrame:
    """Attach final annotations to flows by source IP."""

    annotations = annotation_table.reindex(flows[src_ip_field].astype(str))
    annotations.index = flows.index
    flows[list(ANNOTATION_FIELDS)] = annotations
    return flows


def export_ip_annotation_list(ip_addresses: list, arg: argparse.Namespace, config: dict) -> None:
    """Export IP annotation list to a CSV file.

    This function save all IP addresses and their annotations to a CSV file.
    If the `export_full_annotation`, all annotations are saved. Otherwise, only the final annotation is saved.

    Parameters
    ----------
    ip_addresses : list
        A list of IP addresses to export.
    arg : argparse.Namespace
        Command line arguments.
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
    else:
        filename = f"{arg.dataset.split('.csv')[0]}_ip_annotation_list.csv"

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
            row = [str(ip.ip_addr), bool(ip.multi_device)] + ip.final_annotation.ret_annotation()
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

    annotation_table = _create_annotation_table(ip_addresses)
    flows = _annotate_flows(flows, annotation_table, config["daf"]["src_ip_field"])

    # Export dataset to CSV
    output_file = f"{arg.dataset.split('.csv')[0]}_annotated.csv"
    flows.to_csv(output_file, index=False)

    logger.info(f"Annotated dataset saved to {output_file}")

    return flows


def annotate_dataset_in_chunks(
    dataset: str,
    ip_addresses: list,
    arg: argparse.Namespace,
    config: dict,
    *,
    chunk_size: int = 100_000,
) -> tuple[int, int]:
    """Write the final annotated CSV without loading the complete input."""

    logger.info("  -- Annotating dataset and saving to file...")
    output_file = f"{dataset.split('.csv')[0]}_annotated.csv"
    flow_count = 0
    annotated_count = 0
    first_chunk = True
    annotation_table = _create_annotation_table(ip_addresses)
    src_ip_field = config["daf"]["src_ip_field"]

    for flows in pd.read_csv(
        dataset,
        delimiter=arg.d,
        low_memory=False,
        chunksize=chunk_size,
    ):
        flows = _annotate_flows(flows, annotation_table, src_ip_field)
        flow_count += len(flows)
        annotated_count += int(flows[list(ANNOTATION_FIELDS)].notna().any(axis=1).sum())
        flows.to_csv(
            output_file,
            index=False,
            mode="w" if first_chunk else "a",
            header=first_chunk,
        )
        first_chunk = False

    if first_chunk:
        flows = pd.read_csv(dataset, delimiter=arg.d, low_memory=False)
        _annotate_flows(flows, annotation_table, src_ip_field).to_csv(output_file, index=False)

    logger.info(f"Annotated dataset saved to {output_file}")
    return flow_count, annotated_count
