#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: taxonomy_checker.py
Description: Handles loading and validation of OS and device taxonomies from JSON files.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from config import Configurable, Requirement

if TYPE_CHECKING:
    from annotation import Annotation

logger = logging.getLogger("TaxonomyChecker")


class TaxonomyChecker(Configurable):
    """
    Handles loading and validation of OS and device taxonomies from JSON files.

    Attributes
    ----------
    os_tax : dict[str, list[str]]
        Dictionary representing the loaded OS taxonomy.
    dev_tax : dict[str, list[str]]
        Dictionary representing the loaded device taxonomy.

    """

    REQUIREMENTS = (
        Requirement("os_taxonomy_path", str, path="file"),
        Requirement("device_taxonomy_path", str, path="file"),
    )

    @classmethod
    def from_config(cls, config: dict) -> TaxonomyChecker:
        """Create the checker from the taxonomy paths of the ``daf`` section.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.

        Returns
        -------
        TaxonomyChecker
            Loaded taxonomies.
        """

        daf_config = cls.check_config(config["daf"], "daf")
        return cls(daf_config["os_taxonomy_path"], daf_config["device_taxonomy_path"])

    def __init__(self, os_tax_file: str, dev_tax_file: str):
        """
        Initializes the Taxonomy object by loading operating system and device taxonomies.

        Parameters
        ----------
        os_tax_file : str
            Path to the JSON file containing the OS taxonomy.
        dev_tax_file : str
            Path to the JSON file containing the device taxonomy.
        """
        os_file = Path(os_tax_file)
        dev_file = Path(dev_tax_file)

        if not os_file.exists():
            logger.error(f"OS taxonomy file '{os_tax_file}' does not exist.")
            raise FileNotFoundError(f"OS taxonomy file '{os_tax_file}' does not exist.")
        if not dev_file.exists():
            logger.error(f"Device taxonomy file '{dev_tax_file}' does not exist.")
            raise FileNotFoundError(f"Device taxonomy file '{dev_tax_file}' does not exist.")

        self.os_tax = self.load_json(os_file)
        self.dev_tax = self.load_json(dev_file)

    @staticmethod
    def load_json(file_path: Path) -> dict[str, list[str]]:
        """
        Load a taxonomy from a JSON file.

        This method loads either an operating system taxonomy or a device type taxonomy,
        depending on the provided file. The taxonomy file must be a JSON object where
        each key is a taxonomy category (e.g., OS family or device group) and each value
        is a list of strings representing subcategories (e.g., OS types or device classes).

        Parameters
        ----------
        file_path : Path
            Path to the JSON file containing the OS/dev taxonomy.

        Returns
        -------
        dict[str, list[str]]
            A dictionary mapping taxonomy categories to lists of subcategory strings.

        Raises
        ------
        FileNotFoundError
            If the specified taxonomy file does not exist.
        json.JSONDecodeError
            If the file is not a valid JSON or cannot be parsed.

        """

        if not file_path.exists():
            raise FileNotFoundError(f"OS taxonomy file '{file_path}' does not exist.")

        with open(file_path, "r") as f:
            os_tax = json.load(f)

        return os_tax

    def check_annotation(self, annotation: Annotation) -> bool:
        """
        Check if the given annotation matches the OS and device criteria.

        Parameters
        ----------
        annotation : Annotation
            An annotation object containing information about group, class, OS family, OS type, and OS version.

        Returns
        -------
        bool
            True if both the OS and device checks pass, False otherwise.
        """

        group, _class, os_family, os_type, os_version = annotation.ret_annotation()

        if self.check_os(os_family, os_type, os_version) and self.check_device(group, _class):
            return True

        return False

    def check_os(self, os_family: str, os_type: str, os_version: str) -> bool:
        """
        Check if the specified operating system family and type exist in the taxonomy.

        Parameters
        ----------
        os_family : str
            The operating system family to check (e.g., 'Linux', 'Windows').
        os_type : str
            The operating system type to check within the family (e.g., 'Ubuntu', 'Server').
        os_version : str
            The version of the operating system (currently unused, versions dont have taxonomy).

        Returns
        -------
        bool
            True if the OS family and type exist in the taxonomy, False otherwise.

        """

        if os_family in self.os_tax and (os_type is None or os_type in self.os_tax[os_family]):
            return True
        return False

    def check_device(self, group: str, _class: str) -> bool:
        """
        Check if a device group and class exist in the device taxonomy.

        Parameters
        ----------
        group : str
            The device group to check.
        _class : str
            The device class to check within the specified group.

        Returns
        -------
        bool
            True if the group exists in the device taxonomy and the class exists within that group, False otherwise.
        """

        if group in self.dev_tax and (_class is None or _class in self.dev_tax[group]):
            return True
        return False
