#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: annotation.py
Description: Defines the Annotation class for representing and annotating objects,
including methods for setting, exporting, importing, and checking annotation data.
"""

import logging
from typing import TypeVar

from pandas import isna

from taxonomy_checker import TaxonomyChecker

TAnnotation = TypeVar("TAnnotation", bound="Annotation")

logger = logging.getLogger("Annotation")


class Annotation:
    # Shared taxonomy checker instance
    _taxonomy_checker: TaxonomyChecker = None

    @classmethod
    def initialize_taxonomy_checker(cls, os_tax_file: str, dev_tax_file: str) -> None:
        """
        Initialize the shared taxonomy checker instance.

        Parameters
        ----------
        os_tax_file : str
            Path to the operating system taxonomy file.
        dev_tax_file : str
            Path to the device taxonomy file.
        """
        cls._taxonomy_checker = TaxonomyChecker(os_tax_file, dev_tax_file)

    @classmethod
    def set_taxonomy_checker(cls, checker: TaxonomyChecker) -> None:
        """
        Set the shared taxonomy checker instance.

        Parameters
        ----------
        checker : TaxonomyChecker
            Loaded taxonomies.
        """
        cls._taxonomy_checker = checker

    @classmethod
    def _get_taxonomy(cls) -> TaxonomyChecker:
        """
        Returns the configured taxonomy checker instance.
        This method retrieves the taxonomy checker object associated with the class.
        If the taxonomy checker has not been configured, it logs an error and raises
        a RuntimeError. The taxonomy checker must be configured beforehand using
        `Annotation.configure_taxonomy(os_tax_path, dev_tax_path)`.

        Returns
        -------
        TaxonomyChecker
            The configured taxonomy checker instance.

        Raises
        ------
        RuntimeError
            If the taxonomy checker is not configured.
        """

        if cls._taxonomy_checker is None:
            logger.error(
                "Annotation taxonomy is not configured. Call Annotation.configure_taxonomy(os_tax_path, dev_tax_path) first."
            )
            raise RuntimeError("Annotation taxonomy is not configured.")

        return cls._taxonomy_checker

    def __init__(
        self: TAnnotation,
        group: str = None,
        _class: str = None,
        os_family: str = None,
        os_type: str = None,
        os_version: str = None,
    ) -> None:
        """Initialize a new instance of the TAnnotation class.

        Parameters
        ----------
        self : TAnnotation
            The current instance of the TAnnotation class.
        group : str, optional
            The group of the annotation, by default None.
        _class : str, optional
            The class of the annotation, by default None.
        os_family : str, optional
            The operating system family of the annotation, by default None.
        os_type : str, optional
            The operating system type of the annotation, by default None.
        os_version : str, optional
            The operating system version of the annotation, by default None.
        """
        self.group = None
        self._class = None
        self.os_family = None
        self.os_type = None
        self.os_version = None
        self.set_annotation(group, _class, os_family, os_type, os_version)

    def set_annotation(
        self: TAnnotation,
        group_label: str,
        _class_label: str,
        os_family_label: str,
        os_type_label: str,
        os_version_label: str,
    ) -> None:
        """Set the annotation for the object.
        This method sets the annotation for the object with the provided group, class, OS family, OS type, and OS version.
        Empty strings are converted to None.

        Parameters
        ----------
        self : TAnnotation
            The current instance of the TAnnotation class.
        group_label : str
            The group of the annotation.
        _class_label : str
            The class of the annotation.
        os_family_label : str
            The OS family of the annotation.
        os_type_label : str
            The OS type of the annotation.
        os_version_label : str
            The OS version of the annotation.
        """

        def _validate_label(label: str, field_name: str):
            """Validate and normalize a label."""
            if isna(label):
                return None
            elif isinstance(label, str):
                if len(label) == 0:
                    return None
                else:
                    return label.lower()
            else:
                logger.warning(
                    f"Invalid type for {field_name}, expecpected str or None not type:{type(label)}, value:{label}"
                )
                return None

        os_family = _validate_label(os_family_label, "os_family")
        os_type = _validate_label(os_type_label, "os_type")
        os_version = _validate_label(os_version_label, "os_version")
        group = _validate_label(group_label, "group")
        _class = _validate_label(_class_label, "class")

        tax_checker = self._get_taxonomy()
        if tax_checker.check_os(os_family, os_type, os_version):
            self.os_family = os_family
            self.os_type = os_type
            self.os_version = os_version
        elif os_family:
            logger.warning(
                f"OS annotation not set, invalid OS taxonomy: {os_family}, {os_type}, {os_version}"
            )

        if tax_checker.check_device(group, _class):
            self.group = group
            self._class = _class
        elif group:
            logger.warning(f"Device annotation not set, invalid device taxonomy: {group}, {_class}")

    def ret_annotation(self: TAnnotation) -> list:
        """Return the annotation as a list.

        This method returns the annotation attributes as a list.

        Parameters
        ----------
        self : TAnnotation
            The TAnnotation object.

        Returns
        -------
        list
            A list containing the annotation attributes, including group, class,
            os_family, os_type, and os_version.
        """

        return [self.group, self._class, self.os_family, self.os_type, self.os_version]

    def is_empty(self: TAnnotation) -> bool:
        """Check if the annotation is empty.

        This method checks if all the attributes of the annotation are None or have a length of 0.

        Parameters
        ----------
        self : TAnnotation
            The annotation object.

        Returns
        -------
        bool
            True if the annotation is empty, False otherwise.
        """

        return all(
            [
                (self.group is None or len(self.group) == 0),
                (self._class is None or len(self._class) == 0),
                (self.os_family is None or len(self.os_family) == 0),
                (self.os_type is None or len(self.os_type) == 0),
                (self.os_version is None or len(self.os_version) == 0),
            ]
        )

    def export(self) -> dict:
        """Export the annotation as a serializable dictionary.

        Returns
        -------
        dict
            A dictionary representation of the annotation, suitable for serialization.
        """

        return {
            "group": self.group,
            "class": self._class,
            "os_family": self.os_family,
            "os_type": self.os_type,
            "os_version": self.os_version,
        }

    @classmethod
    def load(cls, data: dict) -> TAnnotation:
        """Load the annotation from a dictionary.

        Parameters
        ----------
        data : dict
            A dictionary containing the annotation data. It should have keys
            "group", "class", "os_family", "os_type", and "os_version".

        Returns
        -------
        TAnnotation
            Created instance of the Annotation class.
        """

        return cls(
            group=data.get("group"),
            _class=data.get("class"),
            os_family=data.get("os_family"),
            os_type=data.get("os_type"),
            os_version=data.get("os_version"),
        )
