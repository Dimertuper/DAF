#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: hostname_annotator.py
Description: Hostname annotator module used to annotate IP addresses with hostname-based metadata.
"""

import logging
import operator as op
import socket
import time
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd

from config import Requirement
from core import IPAnnotator
from ip import Annotation

logger = logging.getLogger("Hostname Annotator")


class HostnameRules:
    """Rules mapping reverse DNS hostnames to annotations.

    Three rule sets are used, in this order:

    - full-match: the complete hostname,
    - sequences: labels of the hostname (split by dots),
    - subsequences: substrings of the first label (sequences are included too).

    Attributes
    ----------
    full_match : dict
        Hostname mapped to annotation fields.
    sequences : dict
        Hostname label mapped to annotation fields.
    subsequences : dict
        Substring mapped to annotation fields.
    """

    FIELDS = ("group", "class", "os-family", "os-type", "os-version")

    def __init__(self, full_db: Path, sequences_db: Path, subsequences_db: Path) -> None:
        """Load the rules from CSV files.

        Parameters
        ----------
        full_db : pathlib.Path
            CSV with the column ``hostname`` and the annotation fields.
        sequences_db : pathlib.Path
            CSV with the column ``sequence`` and the annotation fields.
        subsequences_db : pathlib.Path
            CSV with the column ``subsequence`` and the annotation fields.

        Raises
        ------
        FileNotFoundError
            If any of the files does not exist.
        """

        paths = [full_db, sequences_db, subsequences_db]
        if not all(p.exists() for p in paths):
            logger.error(f"Annotation file {paths} does not exist")
            raise FileNotFoundError(f"Hostname Annotator, path to database: {paths} does not exist")

        self.full_match = pd.read_csv(full_db).set_index("hostname").to_dict("index")
        self.sequences = pd.read_csv(sequences_db).set_index("sequence").to_dict("index")
        self.subsequences = pd.read_csv(subsequences_db).set_index("subsequence").to_dict("index")
        self.subsequences.update(self.sequences)

    @classmethod
    def _annotation(cls, rule: dict) -> Annotation:
        """Create an annotation from the fields of one rule."""

        return Annotation(*(rule[field] for field in cls.FIELDS))

    @staticmethod
    def _combine(rules: List[dict]) -> Tuple[Optional[Annotation], bool]:
        """Combine the rules matched by the sequences or subsequences of a hostname.

        Parameters
        ----------
        rules : list
            Matched rules in the order of matching.

        Returns
        -------
        tuple
            The annotation (or None) and whether the search is finished. One rule or
            rules of one group and class finish the search. Rules of one group with
            different classes give an annotation without class but do not finish it.
            Rules of different groups finish the search without an annotation.
        """

        groups = [rule["group"] for rule in rules]
        classes = [rule["class"] for rule in rules]
        if not rules:
            return None, False
        first = rules[0]
        labels = (first["os-family"], first["os-type"], first["os-version"])
        if len(groups) == 1 or (len(set(groups)) == 1 and len(set(classes)) == 1):
            return Annotation(groups[0], classes[0], *labels), True
        if len(set(groups)) == 1:
            return Annotation(groups[0], None, *labels), False
        return None, True

    def annotation_for(self, hostname: str) -> Optional[Annotation]:
        """Return the annotation of a hostname.

        Parameters
        ----------
        hostname : str
            Reverse DNS hostname.

        Returns
        -------
        Annotation or None
            Annotation of the first rule set that decides.
        """

        if hostname in self.full_match:
            return self._annotation(self.full_match[hostname])

        labels = hostname.split(".")
        annotation, finished = self._combine(
            [self.sequences[label] for label in labels if label in self.sequences]
        )
        if finished:
            return annotation

        subsequence, _ = self._combine(
            [rule for key, rule in self.subsequences.items() if op.contains(labels[0], key)]
        )
        return subsequence if subsequence is not None else annotation


class ReverseDNS:
    """Rate limited reverse DNS lookups.

    Attributes
    ----------
    timeout : float
        Minimal delay between two lookups in seconds.
    """

    def __init__(self, timeout: float) -> None:
        """Initialize the resolver.

        Parameters
        ----------
        timeout : float
            Minimal delay between two lookups in seconds.
        """

        self.timeout = timeout
        self._timestamp = time.time()

    def resolve(self, ip: str) -> Optional[str]:
        """Return the hostname of an IP address.

        Parameters
        ----------
        ip : str
            IP address.

        Returns
        -------
        str or None
            Hostname, or None if it cannot be determined.
        """

        elapsed = time.time() - self._timestamp
        if elapsed < self.timeout:
            time.sleep(self.timeout - elapsed)
        self._timestamp = time.time()

        try:
            return socket.getnameinfo((ip, 0), 0)[0]
        except socket.gaierror:
            return None


class HostnameAnnotator(IPAnnotator):
    """Annotate IP addresses by rules matched against their reverse DNS hostname.

    Attributes
    ----------
    rules : HostnameRules
        Loaded rules.
    resolver : ReverseDNS
        Resolver of hostnames.
    """

    name = "hostname_annotator"
    description = "reverse DNS queries annotation"
    REQUIREMENTS = (
        Requirement("full_db", str),
        Requirement("sequences_db", str),
        Requirement("subsequences_db", str),
        Requirement("timeout", (int, float), default=0.00001, minimum=0),
    )

    def setup(self) -> None:
        """Load the hostname rules."""

        self.rules = HostnameRules(
            Path(self.config["full_db"]),
            Path(self.config["sequences_db"]),
            Path(self.config["subsequences_db"]),
        )
        self.resolver = ReverseDNS(self.config["timeout"])

    def annotate_ip(self, ip) -> None:
        """Resolve the hostname of one IP address and annotate it.

        Parameters
        ----------
        ip : IP
            IP object to annotate.
        """

        hostname = self.resolver.resolve(str(ip.ip_addr))
        if hostname is None:
            return
        ip.add_data("hostname_annotator", hostname)

        annotation = self.rules.annotation_for(hostname)
        if annotation is not None:
            ip.add_annotation("hostname_annotator", annotation)
