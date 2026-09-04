#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: load.py
Description: Functions for loading DAF configuration and annotators, including validation and dynamic module import.
"""

import importlib.util
import logging
from argparse import Namespace
from pathlib import Path

import yaml

from windows import parse_duration

logger = logging.getLogger("Load")


def validate_windowing_config(config: dict) -> None:
    """Validate the optional ``daf.windowing`` configuration."""

    windowing = config["daf"].get("windowing")
    if windowing is None:
        return
    if not isinstance(windowing, dict):
        raise ValueError("DAF:: daf.windowing must be a mapping")
    if not isinstance(windowing.get("enabled"), bool):
        raise ValueError("DAF:: daf.windowing.enabled must be true or false")
    if not windowing["enabled"]:
        return

    window_type = windowing.get("type")
    if window_type not in {"rows", "time"}:
        raise ValueError("DAF:: daf.windowing.type must be 'rows' or 'time'")
    if windowing.get("consensus") != "majority":
        raise ValueError("DAF:: not supported daf.windowing.consensus, supported are: 'majority'")

    size = windowing.get("size")
    if window_type == "rows":
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError("DAF:: row window size must be a positive integer")
        return

    timestamp_field = windowing.get("timestamp_field")
    if not isinstance(timestamp_field, str) or not timestamp_field:
        raise ValueError("DAF:: time windowing requires timestamp_field")
    parse_duration(size)


def load_config(arg: Namespace) -> dict:
    conf_path = Path(arg.config)

    if not conf_path.exists():
        logger.error("Config file not found")
        raise FileNotFoundError("DAF:: config file not found")

    with conf_path.open("r", encoding="utf-8") as file:
        try:
            config = yaml.safe_load(file)
        except yaml.YAMLError:
            logger.error("Config file is not valid YAML")
            raise ValueError("DAF:: config file is not valid YAML")

    if (
        "daf" not in config
        or "min_annotation_count" not in config["daf"]
        or "min_annotators_count" not in config["daf"]
        or "src_ip_field" not in config["daf"]
        or "ip_ranges" not in config["daf"]
        or "threads" not in config["daf"]
        or "export_full_annotation" not in config["daf"]
        or "data_export" not in config["daf"]
        or "annotators_path" not in config["daf"]
        or "detectors_path" not in config["daf"]
        or "os_taxonomy_path" not in config["daf"]
        or "device_taxonomy_path" not in config["daf"]
    ):
        logger.error(
            "Config file does not contain DAF module config or one of the required fields: "
            "min_annotation_count, min_annotators_count, src_ip_field, ip_ranges, threads, "
            "export_full_annotation, data_export, annotators_path, detectors_path, os_taxonomy_path, device_taxonomy_path"
        )
        raise ValueError(
            "DAF:: Configuration of DAF module is missing in config file or its incomplete"
        )

    config["daf"]["progress_print"] = arg.logfile is True
    validate_windowing_config(config)

    return config


def load_modules(config: dict) -> list:
    """Load annotators based on the provided configuration.

    This function searches for annotator files in the specified annotators_path
    and loads them as modules. If the annotators are not found, the function checks the configuration.

    Parameters
    ----------
    config : dict
        The configuration dictionary containing information about the annotators.

    Returns
    -------
    list
        A list of loaded annotator modules.

    Raises
    ------
    ValueError
        If the annotators_path is not specified or incorrect in the configuration.
    """

    annotators_files = []

    annotators_path = Path(config["daf"]["annotators_path"])
    detector_path = Path(config["daf"]["detectors_path"])

    # Find modules files
    for path in [annotators_path, detector_path]:
        if not path.is_dir():
            logger.error("DAF:: annotators_path or detectors_path doesnt exist: {}".format(path))
            raise ValueError("DAF:: Invalid path to annotators or detectors directory")
        for folder in path.iterdir():
            if not folder.is_dir():
                continue
            for file in folder.iterdir():
                if file.name.endswith("annotator.py") or file.name.endswith("detector.py"):
                    annotator_name = file.name.split(".")[0]
                    if annotator_name not in config:
                        logger.warning(
                            "DAF:: Found annotator={}, but configuration is missing in config file, skipping.".format(
                                annotator_name
                            )
                        )
                        continue
                    if config[annotator_name]["enabled"] is True:
                        annotators_files.append(file)
                        config[annotator_name]["loaded"] = True

    # If not all modules are loaded, load them manually
    for name, data in config.items():
        if name == "daf" or "loaded" in data or data["enabled"] is False:
            continue
        if data["path"] == "auto":
            logger.warning(
                "DAF:: Unable to locate annotator={}. Please write path to the config file or place annotator into the 'annotators_path'".format(
                    name
                )
            )
            continue
        if not Path(data["path"]).is_file():
            logger.warning(
                "DAF:: Unable to locate annotator={} at path={}".format(name, data["path"])
            )
            continue

        annotators_files.append(Path(data["path"]))

    # Import annotators
    annotators = []
    for annotator_path in annotators_files:
        # Create module name
        module_name = ".".join(annotator_path.with_suffix("").parts)
        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, annotator_path)
        annotators.append(importlib.util.module_from_spec(spec))
        spec.loader.exec_module(annotators[-1])

    return annotators
