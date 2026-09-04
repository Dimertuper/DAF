#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: daf.py
Description: Main entry point for the Device Annotation Framework (DAF). Handles argument parsing, configuration loading, annotation processing, and logging.
"""

# Standard Libraries Imports
import argparse
import logging
import time
import traceback
from argparse import RawTextHelpFormatter
from copy import deepcopy
from datetime import timedelta
from functools import partial
from pathlib import Path
from threading import Thread

# Third Party Libraries Imports
import pandas as pd

from annotation import Annotation

# Local Imports
from ip import IP, export_ip_data, load_ip_data
from ip_ranges import select_protected_ips
from load import load_config, load_modules, validate_windowing_config
from output import annotate_dataset, annotate_dataset_in_chunks, export_ip_annotation_list
from stats import print_annotation_stats
from windows import (
    WindowResult,
    extend_time_window_results,
    iter_flow_windows,
    resolve_window_results,
)

logger = logging.getLogger("DAF")


def setup_logging(logfile) -> None:
    """
    Set up logging configuration based on logfile parameter.

    Parameters
    ----------
    logfile : bool or str
        Determines the logging configuration:
        - If `True`, logs are printed to the console.
        - If a `str`, logs are written to the specified file.
        - If `False`, logging is disabled.

    Returns
    -------
    None

    """

    if logfile is True:
        logging.basicConfig(
            level=logging.DEBUG,
            format="{asctime} - {levelname} - {name} : {message}",
            style="{",
            datefmt="%d-%m-%Y %H:%M",
        )
    elif isinstance(logfile, str):
        logging.basicConfig(
            filename=logfile,
            filemode="a",
            level=logging.DEBUG,
            format="{asctime} - {levelname} - {name} : {message}",
            style="{",
            datefmt="%d-%m-%Y %H:%M",
        )
    else:
        logging.disable(logging.CRITICAL)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="""

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "--config",
        help="Define path to DAFs configuration file. Default: './daf_config.yml'",
        type=str,
        default="daf_config.yml",
        required=True,
    )

    parser.add_argument(
        "--dataset",
        help="Dataset CSV file for annotation.",
        type=str,
        metavar="FILE.csv",
        default=None,
    )

    parser.add_argument(
        "--logfile",
        help="Define logging output. If True, logs are printed to console. If file, logs are saved to file. If False, logging is disabled. Default: True",
        type=str,
        default=True,
    )

    parser.add_argument(
        "-d",
        help="Delimiter of input dataset. Default: ','",
        type=str,
        metavar="CHAR",
        default=",",
    )

    parser.add_argument(
        "--reannotation",
        help="Filling the raw annotation information file into this parameter process to reannotate dataset. Default: disabled",
        type=str,
        default=None,
    )

    return parser.parse_args()


def process_flows(flows: pd.DataFrame, config: dict, annotators: list) -> list[IP]:
    """Run the existing DAF annotators against one flow DataFrame."""

    def start_thread(module, ip_addresses, config, flows_ip_dict):
        """Start annotator in a separate thread.
        Necessary for catching errors in annotators.

        Parameters
        ----------
        module : type
            The annotator module to be executed.
        ip_addresses : list
            The list of IP addresses to be annotated.
        config : dict
            Configuration dictionary.
        flows_ip_dict : dict
            A dictionary mapping IP addresses to their corresponding network flows.
        """

        try:
            module.annotate(ip_addresses, config, flows_ip_dict)
            logger.info(f"    -- {module.__name__} finished.")
        except Exception as e:
            thread_errors.append([module.__name__, traceback.format_exc()])

    thread_errors = []

    logger.info("  -- getting IP addresses for annotation from dataset ... ")
    ip_addresses = select_protected_ips(config, flows)

    grouped_flows = flows.groupby(config["daf"]["src_ip_field"])
    flows_ip_dict = {ip: group for ip, group in grouped_flows}

    threads = []
    logger.info("  -- Starting annotators:")
    for module in annotators:
        logger.info(f"    -- {module.__name__} started ... ")
        if config["daf"]["threads"]:
            thread = Thread(
                target=partial(start_thread, module, ip_addresses, config, flows_ip_dict)
            )
            threads.append(thread)
            thread.start()
        else:
            logger.info(f"    -- {module.__name__} started (sequential)... ")
            module.annotate(ip_addresses, config, flows_ip_dict)
            logger.info(f"    -- {module.__name__} finished. ")

    # Wait for threads to finish
    if config["daf"]["threads"]:
        for thread in threads:
            thread.join()

    # Check for errors in modules
    if thread_errors:
        for module, message in thread_errors:
            logger.error(f"Module: {module}\n{message}")
        logger.error("Some modules failed.")
        logger.error("Exiting annotation process.")
        raise RuntimeError("Some modules failed. Exiting annotation process.")

    logger.info("  -- all annotators finished")

    # Finalize annotation of IPs
    logger.info("  -- finalize annotation of IPs ... ")
    logger.info(f"    -- minimum annotators count: {config['daf']['min_annotators_count']}")
    logger.info(f"    -- minimum annotation count: {config['daf']['min_annotation_count']}")
    for ip in ip_addresses:
        ip.perform_annotation(config["daf"]["min_annotators_count"])
    logger.info("  -- finalize annotation of IPs ... DONE")
    return ip_addresses


def process_dataset(arg: argparse.Namespace, config: dict, annotators: list) -> None:
    """Annotate the complete dataset in one DAF pass."""

    logger.info("Process annotation in memory:")
    logger.info("  -- loading complete dataset to memory ... ")
    flows = pd.read_csv(arg.dataset, delimiter=arg.d, low_memory=False)
    ip_addresses = process_flows(flows, config, annotators)

    # Export annotation
    export_ip_annotation_list(ip_addresses, arg, config)
    flows = annotate_dataset(flows, ip_addresses, arg, config)

    # Export annotation data
    if config["daf"]["data_export"]:
        export_ip_data(ip_addresses, arg)

    # Print annotation stats
    print_annotation_stats(ip_addresses, config, flows)


def process_windows(arg: argparse.Namespace, config: dict, annotators: list) -> None:
    """Run the normal DAF pipeline once per configured window."""

    validate_windowing_config(config)
    logger.info("Process annotation in windows:")
    windowing = config["daf"]["windowing"]
    results = []
    for flow_window in iter_flow_windows(
        arg.dataset,
        delimiter=arg.d,
        config=windowing,
    ):
        logger.info(f"  -- processing window {flow_window.metadata.index} ...")
        ip_addresses = process_flows(flow_window.flows, config, annotators)
        results.append(WindowResult.from_ips(flow_window.metadata, ip_addresses))

    ip_addresses = resolve_window_results(results)
    export_ip_annotation_list(ip_addresses, arg, config)
    chunk_size = windowing["size"] if windowing["type"] == "rows" else 100_000
    flow_stats = annotate_dataset_in_chunks(
        arg.dataset,
        ip_addresses,
        arg,
        config,
        chunk_size=chunk_size,
    )
    if config["daf"]["data_export"]:
        export_ip_data(ip_addresses, arg)
    print_annotation_stats(ip_addresses, config, flow_stats=flow_stats)


def process_reannotation_in_windows(
    arg: argparse.Namespace,
    config: dict,
    annotators: list,
) -> None:
    """Append unseen timestamped observations and recalculate window results."""

    validate_windowing_config(config)
    windowing = config["daf"]["windowing"]
    if windowing["type"] != "time":
        raise ValueError("DAF:: windowed reannotation requires time windows")
    if arg.dataset is None:
        raise ValueError("DAF:: windowed reannotation requires a dataset")

    logger.info("Process reannotation in windows:")
    previous_ips = load_ip_data(arg.reannotation)
    if any(not ip.window_results for ip in previous_ips):
        raise ValueError(
            "DAF:: windowed reannotation requires data produced by time windowing"
        )

    saved_results, _ = extend_time_window_results(
        previous_ips,
        [],
        window_size=windowing["size"],
    )
    saved_observations = {
        (observation.ip_address, result.metadata.start)
        for result in saved_results
        for observation in result.observations
    }

    new_results = []
    for flow_window in iter_flow_windows(
        arg.dataset,
        delimiter=arg.d,
        config=windowing,
    ):
        ip_fields = [config["daf"]["src_ip_field"]]
        if config["daf"]["dst_ip_field"] is not None:
            ip_fields.append(config["daf"]["dst_ip_field"])
        unseen_rows = pd.Series(False, index=flow_window.flows.index)
        for field in ip_fields:
            unseen_rows |= pd.Series(
                [
                    (str(ip_address), flow_window.metadata.start)
                    not in saved_observations
                    for ip_address in flow_window.flows[field]
                ],
                index=flow_window.flows.index,
            )
        if not unseen_rows.any():
            continue

        logger.info(f"  -- processing window {flow_window.metadata.index} ...")
        ip_addresses = process_flows(
            flow_window.flows[unseen_rows].copy(), config, annotators
        )
        new_results.append(WindowResult.from_ips(flow_window.metadata, ip_addresses))

    merged_results, appended_ips = extend_time_window_results(
        previous_ips,
        new_results,
        window_size=windowing["size"],
    )
    if appended_ips:
        ip_addresses = resolve_window_results(merged_results)
        previous_by_ip = {str(ip.ip_addr): ip for ip in previous_ips}
        for ip in ip_addresses:
            previous = previous_by_ip.get(str(ip.ip_addr))
            if previous is None:
                continue
            ip.data = {**deepcopy(previous.data), **ip.data}
            ip.hand_miss = deepcopy(previous.hand_miss) + ip.hand_miss
            ip.one_miss = deepcopy(previous.one_miss) + ip.one_miss
    else:
        ip_addresses = previous_ips

    export_ip_annotation_list(ip_addresses, arg, config)
    flow_stats = annotate_dataset_in_chunks(
        arg.dataset,
        ip_addresses,
        arg,
        config,
    )
    if config["daf"]["data_export"]:
        export_ip_data(ip_addresses, arg)
    print_annotation_stats(ip_addresses, config, flow_stats=flow_stats)


def process_reannotation(arg: argparse.Namespace, config: dict, annotators: list) -> None:
    """
    Process reannotation using existing annotation file and optionally new dataset.

    Parameters
    ----------
    arg : argparse.Namespace
        Command-line arguments.
    config : dict
        Configuration dictionary.
    annotators : list
        List of annotator modules.
    """

    def start_thread(module, ip_addresses, config, flows_ip_dict):
        """Start annotator in a separate thread.
        Necessary for catching errors in annotators.

        Parameters
        ----------
        module : type
            The annotator module to be executed.
        ip_addresses : list
            The list of IP addresses to be annotated.
        config : dict
            The configuration dictionary.
        flows_ip_dict : dict
            A dictionary mapping IP addresses to their corresponding network flows.
        """

        try:
            module.annotate(ip_addresses, config, flows_ip_dict)
            logger.info(f"    -- {module.__name__} finished.")
        except Exception as e:
            thread_errors.append([module.__name__, traceback.format_exc()])

    new_ips = None

    logger.info("Process reannotation:")

    logger.info(f"  -- loading raw annotation information from {arg.reannotation} ... ")
    ip_addresses_loaded = load_ip_data(arg.reannotation)

    # Check for new IPs that are not in the loaded data
    if arg.dataset is not None:
        logger.info("  -- loading complete dataset to memory ... ")
        flows = pd.read_csv(arg.dataset, delimiter=arg.d, low_memory=False)

        logger.info("  -- getting IP addresses for annotation from dataset ... ")
        ip_addresses_dataset = select_protected_ips(config, flows)

        for ip in ip_addresses_dataset:
            if ip.ip_addr not in ip_addresses_loaded:
                if new_ips is None:
                    logger.info(
                        "IP not found in loaded IP data, starting additional annotation processes for unseen IPs."
                    )
                    new_ips = []
                new_ips.append(IP(ip))

    # If there are new IPs, start annotation processes for them
    if new_ips is not None:
        logger.info("  -- starting additional annotation processes for unseen IPs ... ")
        grouped_flows = flows.groupby(config["daf"]["src_ip_field"])
        flows_ip_dict = {
            str(ip.ip_addr): group
            for ip, group in grouped_flows
            if str(ip.ip_addr) in [str(new_ip.ip_addr) for new_ip in new_ips]
        }

        threads = []
        for module in annotators:
            logger.info(f"    -- {module.__name__} started ... ")
            if config["daf"]["threads"]:
                thread = Thread(
                    target=partial(start_thread, module, new_ips, config, flows_ip_dict)
                )
                threads.append(thread)
                thread.start()
            else:
                logger.info(f"    -- {module.__name__} started (sequential)... ")
                module.annotate(new_ips, config, flows_ip_dict)
                logger.info(f"    -- {module.__name__} finished. ")

        # Wait for threads to finish
        if config["daf"]["threads"]:
            for thread in threads:
                thread.join()

        logger.info("  -- all annotators finished")

    # Finalize annotation of IPs
    logger.info("  -- finalize annotation of IPs ... ")
    logger.info(f"    -- minimum annotators count: {config['daf']['min_annotators_count']}")
    logger.info(f"    -- minimum annotation count: {config['daf']['min_annotation_count']}")

    if new_ips is not None:
        ip_addresses = ip_addresses_dataset + new_ips
    else:
        ip_addresses = ip_addresses_loaded

    for ip in ip_addresses:
        ip.perform_annotation(config["daf"]["min_annotators_count"])
    logger.info("  -- finalize annotation of IPs ... DONE")

    # Export annotation
    export_ip_annotation_list(ip_addresses, arg, config)
    if arg.dataset is not None:
        flows = annotate_dataset(flows, ip_addresses, arg, config)

    # Export annotation data
    # Print annotation stats
    if config["daf"]["data_export"] and new_ips is not None:
        export_ip_data(ip_addresses, arg)
        print_annotation_stats(ip_addresses, config, flows)
    else:
        print_annotation_stats(ip_addresses, config, None)


def main() -> None:
    """Main function to run the Device Annotation Framework (DAF).
    This function initializes the logging, parses command-line arguments, loads the configuration,
    loads the annotators, and starts the annotation process.
    """

    # Parse arguments
    arg = parse_arguments()
    if arg.logfile is None:
        raise ValueError("No logfile specified. Exiting.")
    if arg.dataset is None and arg.reannotation is None:
        raise ValueError("No dataset or reannotation file specified. Exiting.")

    # Start logging
    setup_logging(arg.logfile)
    logger.info("\n" * 2 + "=" * 50 + " Device Annotation Framework (DAF) " + "=" * 50 + "\n")

    # Load configuration
    logger.info(f"Loading configuration from {arg.config} ... ")
    config = load_config(arg)
    windowing_enabled = config["daf"].get("windowing", {}).get("enabled", False)

    # Log the configuration and info about the dataset and reannotation file
    if arg.dataset is not None:
        logger.info(f"Working with dataset: {arg.dataset}")
    if arg.reannotation is not None:
        logger.info(f"Working with reannotation file: {arg.reannotation}")
    if arg.dataset is not None and arg.reannotation is not None:
        logger.info(
            "Both dataset and reannotation file specified. Reannotation will be performed on the dataset."
        )

    # Load annotators
    logger.info("Loading annotators ... ")
    annotators = load_modules(config)
    logger.info("Loaded annotators:")
    for x in annotators:
        logger.info(f"\t{x.__name__}")

    # Initialize taxonomy_checker
    Annotation.initialize_taxonomy_checker(
        config["daf"]["os_taxonomy_path"], config["daf"]["device_taxonomy_path"]
    )

    # Start annotation
    start = time.time()
    if arg.reannotation is None:
        if windowing_enabled:
            process_windows(arg, config, annotators)
        else:
            process_dataset(arg, config, annotators)
    elif windowing_enabled:
        process_reannotation_in_windows(arg, config, annotators)
    else:
        process_reannotation(arg, config, annotators)
    elapsed = time.time() - start
    logger.info(f"Annotation finished in time: {timedelta(seconds=elapsed)}\n\n")
    logging.shutdown()


if __name__ == "__main__":
    main()
