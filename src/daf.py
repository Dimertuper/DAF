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
from load import load_config, load_modules
from output import annotate_dataset, export_ip_annotation_list
from stats import print_annotation_stats

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


def collect_module_inputs(annotators: list, config: dict) -> list:
    """Collect optional input sources supplied by annotator modules.

    Annotators that can introduce IP addresses independently of a flow dataset expose
    ``provide_ips(config)``. DAF treats the returned objects generically and does not
    load or interpret the module's source file itself.

    Parameters
    ----------
    annotators : list
        Loaded annotator modules.
    config : dict
        Complete DAF configuration passed to each provider.

    Returns
    -------
    list
        ``(source, ip_addresses)`` tuples. ``source`` is used for standalone
        output naming and ``ip_addresses`` contains initialized :class:`IP` objects.

    Raises
    ------
    TypeError
        If an annotator returns an invalid source name, container, or object type.
    """

    inputs = []
    for module in annotators:
        provider = getattr(module, "provide_ips", None)
        if provider is None:
            continue
        source, ip_addresses = provider(config)
        if not isinstance(source, str) or not isinstance(ip_addresses, list):
            raise TypeError(f"{module.__name__}.provide_ips() returned an invalid value")
        if not all(isinstance(ip, IP) for ip in ip_addresses):
            raise TypeError(f"{module.__name__}.provide_ips() must return IP objects")
        inputs.append((source, ip_addresses))
    return inputs


def merge_ip_lists(*ip_lists: list) -> list:
    """Combine multiple IP lists without duplicating an address.

    Lists are processed from left to right. When an address occurs more than once,
    the first object is retained. This ensures that flow-backed objects win over
    newly supplied module objects and saved reannotation objects win over new ones.
    Evidence from additional sources is copied only when the retained object does
    not already contain data for that source.

    Parameters
    ----------
    *ip_lists : list
        Ordered lists containing :class:`IP` objects.

    Returns
    -------
    list
        Unique IP objects in first-seen order.
    """

    merged = {}
    for ip_list in ip_lists:
        for ip in ip_list:
            ip_addr = str(ip.ip_addr)
            if ip_addr not in merged:
                merged[ip_addr] = ip
                continue

            for source, evidence in ip.data.items():
                if source not in merged[ip_addr].data:
                    merged[ip_addr].add_data(source, evidence)
    return list(merged.values())


def process_in_memory(arg: argparse.Namespace, config: dict, annotators: list) -> None:
    """
    Annotate the union of flow-backed and annotator-provided IP addresses.

    A flow dataset is optional when an enabled annotator supplies IP objects. Modules
    that require flows receive only flow-backed IPs; flow-independent modules receive
    the complete union. Annotation, voting, export, and statistics otherwise follow
    the normal in-memory DAF process.

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

    thread_errors = []

    logger.info("Process annotation in memory:")

    flows = None
    flow_ip_addresses = []
    flows_ip_dict = {}
    if arg.dataset is not None:
        logger.info("  -- loading complete dataset to memory ... ")
        flows = pd.read_csv(arg.dataset, delimiter=arg.d, low_memory=False)

        logger.info("  -- getting IP addresses for annotation from dataset ... ")
        flow_ip_addresses = select_protected_ips(config, flows)

        grouped_flows = flows.groupby(config["daf"]["src_ip_field"])
        flows_ip_dict = {ip: group for ip, group in grouped_flows}

    module_inputs = collect_module_inputs(annotators, config)
    module_ip_addresses = [
        ip
        for _, supplied_ip_addresses in module_inputs
        for ip in supplied_ip_addresses
    ]
    ip_addresses = merge_ip_lists(flow_ip_addresses, module_ip_addresses)
    if not ip_addresses:
        raise ValueError("No IP addresses found in the configured inputs")
    if arg.dataset is None:
        arg.output_source = module_inputs[0][0]

    flow_ip_keys = {str(ip.ip_addr) for ip in flow_ip_addresses}
    flow_targets = [ip for ip in ip_addresses if str(ip.ip_addr) in flow_ip_keys]

    threads = []
    logger.info("  -- Starting annotators:")
    for module in annotators:
        targets = (
            ip_addresses
            if callable(getattr(module, "provide_ips", None))
            else flow_targets
        )
        if not targets:
            logger.info(f"    -- {module.__name__} skipped (no applicable IPs).")
            continue
        logger.info(f"    -- {module.__name__} started ... ")
        if config["daf"]["threads"]:
            thread = Thread(
                target=partial(start_thread, module, targets, config, flows_ip_dict)
            )
            threads.append(thread)
            thread.start()
        else:
            logger.info(f"    -- {module.__name__} started (sequential)... ")
            module.annotate(targets, config, flows_ip_dict)
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

    # Export annotation
    export_ip_annotation_list(ip_addresses, arg, config)
    if flows is not None:
        flows = annotate_dataset(flows, ip_addresses, arg, config)

    # Export annotation data
    if config["daf"]["data_export"]:
        export_ip_data(ip_addresses, arg)

    # Print annotation stats
    print_annotation_stats(ip_addresses, config, flows)


def process_reannotation(arg: argparse.Namespace, config: dict, annotators: list) -> None:
    """
    Reuse saved IP state and annotate only addresses not already present.

    Current flow-backed and annotator-provided IPs are deduplicated before comparison
    with the saved state. Existing objects retain their evidence and annotations. Only
    new objects are passed to annotators, after which saved and new objects are merged
    once for voting and export.

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

    thread_errors = []
    new_ips = []

    logger.info("Process reannotation:")

    logger.info(f"  -- loading raw annotation information from {arg.reannotation} ... ")
    ip_addresses_loaded = load_ip_data(arg.reannotation)
    loaded_ip_keys = {str(ip.ip_addr) for ip in ip_addresses_loaded}

    # Check for new IPs that are not in the loaded data
    flows = None
    flow_ip_addresses = []
    flows_ip_dict = {}
    if arg.dataset is not None:
        logger.info("  -- loading complete dataset to memory ... ")
        flows = pd.read_csv(arg.dataset, delimiter=arg.d, low_memory=False)

        logger.info("  -- getting IP addresses for annotation from dataset ... ")
        flow_ip_addresses = select_protected_ips(config, flows)

    module_inputs = collect_module_inputs(annotators, config)
    module_ip_addresses = [
        ip
        for _, supplied_ip_addresses in module_inputs
        for ip in supplied_ip_addresses
    ]
    current_ip_addresses = merge_ip_lists(flow_ip_addresses, module_ip_addresses)
    new_ips = [ip for ip in current_ip_addresses if str(ip.ip_addr) not in loaded_ip_keys]

    # If there are new IPs, start annotation processes for them
    if new_ips:
        logger.info("  -- starting additional annotation processes for unseen IPs ... ")
        flow_ip_keys = {str(ip.ip_addr) for ip in flow_ip_addresses}
        new_flow_ip_keys = {
            str(ip.ip_addr) for ip in new_ips if str(ip.ip_addr) in flow_ip_keys
        }
        if flows is not None:
            grouped_flows = flows.groupby(config["daf"]["src_ip_field"])
            flows_ip_dict = {
                str(ip): group
                for ip, group in grouped_flows
                if str(ip) in new_flow_ip_keys
            }

        threads = []
        for module in annotators:
            targets = (
                new_ips
                if callable(getattr(module, "provide_ips", None))
                else [ip for ip in new_ips if str(ip.ip_addr) in new_flow_ip_keys]
            )
            if not targets:
                logger.info(f"    -- {module.__name__} skipped (no applicable IPs).")
                continue
            logger.info(f"    -- {module.__name__} started ... ")
            if config["daf"]["threads"]:
                thread = Thread(
                    target=partial(start_thread, module, targets, config, flows_ip_dict)
                )
                threads.append(thread)
                thread.start()
            else:
                logger.info(f"    -- {module.__name__} started (sequential)... ")
                module.annotate(targets, config, flows_ip_dict)
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

    ip_addresses = merge_ip_lists(ip_addresses_loaded, new_ips)

    for ip in ip_addresses:
        ip.perform_annotation(config["daf"]["min_annotators_count"])
    logger.info("  -- finalize annotation of IPs ... DONE")

    # Export annotation
    export_ip_annotation_list(ip_addresses, arg, config)
    if arg.dataset is not None:
        flows = annotate_dataset(flows, ip_addresses, arg, config)

    # Export annotation data
    # Print annotation stats
    if config["daf"]["data_export"] and new_ips:
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

    # Start logging
    setup_logging(arg.logfile)
    logger.info("\n" * 2 + "=" * 50 + " Device Annotation Framework (DAF) " + "=" * 50 + "\n")

    # Load configuration
    logger.info(f"Loading configuration from {arg.config} ... ")
    config = load_config(arg)

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
    if arg.dataset is None and arg.reannotation is None and not any(
        hasattr(module, "provide_ips") for module in annotators
    ):
        raise ValueError("No dataset, reannotation file, or module input specified. Exiting.")

    # Initialize taxonomy_checker
    Annotation.initialize_taxonomy_checker(
        config["daf"]["os_taxonomy_path"], config["daf"]["device_taxonomy_path"]
    )

    # Start annotation
    start = time.time()
    if arg.reannotation is None:
        process_in_memory(arg, config, annotators)
    else:
        process_reannotation(arg, config, annotators)
    elapsed = time.time() - start
    logger.info(f"Annotation finished in time: {timedelta(seconds=elapsed)}\n\n")
    logging.shutdown()


if __name__ == "__main__":
    main()
