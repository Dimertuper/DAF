#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: nmap_annotator.py
Description: Annotate DAF IP objects from an Nmap XML report, imported or produced by DAF.
"""

import csv
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree

from config import Requirement
from core import IPAnnotator, IPSource
from ip import IP, Annotation

logger = logging.getLogger("Nmap Annotator")

MODES = ("passive", "active")

# Baseline scan: TCP SYN scan of the 1000 most common ports with service and OS detection.
DEFAULT_ARGUMENTS = ["-sS", "-sV", "-O", "-n", "-T3", "--top-ports", "1000"]

# Nmap options which need raw sockets, i.e. root or --privileged with capabilities.
PRIVILEGED_OPTIONS = {"-sS", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sO", "-O", "-A"}

# Options set by DAF itself.
RESERVED_OPTIONS = {"-oX", "-oA", "-iL"}

# Maximal number of hosts added to the annotated IPs from one configured network.
MAX_TARGET_HOSTS = 65536

RULE_SOURCES = {
    "os_match_name",
    "os_class_family",
    "os_class_type",
    "os_class_cpe",
    "service_name",
    "service_product",
    "service_version",
    "service_extra_info",
    "service_os_type",
    "service_device_type",
    "service_cpe",
}



class NmapReportParser:
    """Parser of Nmap XML reports into JSON-compatible evidence indexed by IP."""

    @staticmethod
    def get_xml_attributes(element) -> dict:
        """Return an element's attributes, or an empty dictionary if it is absent."""
        return dict(element.attrib) if element is not None else {}

    @staticmethod
    def parse_cpe_element(element) -> dict:
        """Read attributes and CPE identifiers from a service or OS class."""
        if element is None:
            return {}
        result = NmapReportParser.get_xml_attributes(element)
        result["cpes"] = [cpe.text.strip() for cpe in element.findall("cpe") if cpe.text]
        return result

    @staticmethod
    def parse_scan(root) -> dict:
        """Read scan metadata; reject non-Nmap, incomplete, or failed reports."""
        if root.tag != "nmaprun" or root.get("scanner") != "nmap":
            raise ValueError("Nmap Annotator:: XML root is not an Nmap report")

        finished = root.find("./runstats/finished")
        if finished is None:
            raise ValueError("Nmap Annotator:: incomplete XML report (missing run statistics)")
        if finished.get("exit") == "error":
            message = finished.get("errormsg", "Nmap reported an unsuccessful scan")
            raise RuntimeError(f"Nmap Annotator:: {message}")

        scan = {}
        for field in ("args", "start", "startstr", "version", "xmloutputversion"):
            value = root.get(field)
            if value is not None:
                scan[field] = value
        scan["finished"] = NmapReportParser.get_xml_attributes(finished)
        return scan

    @staticmethod
    def get_host_ips(host) -> list:
        """Return normalized IPv4/IPv6 addresses, skipping MACs and invalid addresses."""
        ip_addresses = []
        for address in host.findall("address"):
            if address.get("addrtype") not in ("ipv4", "ipv6"):
                continue

            value = address.get("addr")
            try:
                ip_addr = ipaddress.ip_address(value)
            except ValueError:
                logger.warning(f"Nmap Annotator:: ignoring invalid address: {value}")
                continue
            ip_addresses.append(str(ip_addr))

        return ip_addresses

    @staticmethod
    def parse_ports(host) -> list:
        """Read each port's protocol, number, state, and detected service."""
        ports = []
        for port in host.findall("./ports/port"):
            port_data = {
                "protocol": port.get("protocol"),
                "port": int(port.get("portid")),
                "state": NmapReportParser.get_xml_attributes(port.find("state")),
                "service": NmapReportParser.parse_cpe_element(port.find("service")),
            }
            ports.append(port_data)
        return ports

    @staticmethod
    def parse_os_matches(host) -> list:
        """Read OS fingerprints and their nested classes."""
        matches = []
        for os_match in host.findall("./os/osmatch"):
            match_data = NmapReportParser.get_xml_attributes(os_match)
            match_data["classes"] = []
            for os_class in os_match.findall("osclass"):
                match_data["classes"].append(NmapReportParser.parse_cpe_element(os_class))
            matches.append(match_data)
        return matches

    @staticmethod
    def parse_host(host) -> dict:
        """Collect host timestamps, status, addresses, names, OS evidence, and ports."""
        addresses = []
        for address in host.findall("address"):
            addresses.append(NmapReportParser.get_xml_attributes(address))

        hostnames = []
        for hostname in host.findall("./hostnames/hostname"):
            hostnames.append(NmapReportParser.get_xml_attributes(hostname))

        # Older reports put classes directly under os; newer reports nest them in matches.
        os_classes = []
        for os_class in host.findall("./os//osclass"):
            os_classes.append(NmapReportParser.parse_cpe_element(os_class))

        return {
            "starttime": host.get("starttime"),
            "endtime": host.get("endtime"),
            "status": NmapReportParser.get_xml_attributes(host.find("status")),
            "addresses": addresses,
            "hostnames": hostnames,
            "os_matches": NmapReportParser.parse_os_matches(host),
            "os_classes": os_classes,
            "ports": NmapReportParser.parse_ports(host),
        }

    @staticmethod
    def parse(xml_file: str) -> dict:
        """Parse an Nmap XML report into JSON-compatible evidence indexed by IP.

        Parameters
        ----------
        xml_file : str
            Path to a completed Nmap XML report.

        Returns
        -------
        dict
            Normalized IPv4/IPv6 strings mapped to scan and host evidence dictionaries.

        Raises
        ------
        FileNotFoundError
            If the configured report does not exist.
        ValueError
            If the XML is malformed, is not an Nmap report, or is incomplete.
        RuntimeError
            If Nmap explicitly recorded an unsuccessful scan.
        """

        path = Path(xml_file)
        if not path.is_file():
            logger.error(f"Nmap Annotator:: XML report does not exist: {path}")
            raise FileNotFoundError(f"Nmap Annotator:: XML report does not exist: {path}")

        try:
            root = ElementTree.parse(path).getroot()
        except ElementTree.ParseError as error:
            logger.error(f"Nmap Annotator:: invalid XML report: {path}")
            raise ValueError(f"Nmap Annotator:: invalid XML report: {path}") from error

        scan = NmapReportParser.parse_scan(root)
        evidence_by_ip = {}

        for host in root.findall("host"):
            ip_addresses = NmapReportParser.get_host_ips(host)
            if not ip_addresses:
                continue

            evidence = {"scan": scan, "host": NmapReportParser.parse_host(host)}
            for ip_addr in ip_addresses:
                evidence_by_ip[ip_addr] = evidence

        return evidence_by_ip


class NmapRuleSet:
    """Rules mapping Nmap evidence to DAF labels.

    The CSV database has the columns ``source, pattern, group, class, os_family,
    os_type, os_version``. Patterns are case-insensitive regular expressions matched
    against the Nmap evidence of the source; labels are validated against the taxonomies.

    Attributes
    ----------
    rules : dict
        Rules grouped by evidence source.
    """

    def __init__(self, db_file: str) -> None:
        """Load the rules.

        Parameters
        ----------
        db_file : str
            Path to the CSV rule database.
        """

        self.rules = self.load(db_file)

    def match(self, values: list) -> list:
        """Apply the rules to evidence values.

        Parameters
        ----------
        values : list
            ``(source, value)`` pairs.

        Returns
        -------
        list
            Matched sources with their expanded labels.
        """

        return NmapRuleSet.match_rules(values, self.rules)

    @staticmethod
    def validate_labels(labels: dict, row_number: int) -> None:
        """Reject unknown taxonomy labels or missing parents, reporting the CSV row."""
        group = labels["group"]
        _class = labels["class"]
        os_family = labels["os_family"]
        os_type = labels["os_type"]
        os_version = labels["os_version"]
        taxonomy = Annotation._get_taxonomy()
        if _class and not group:
            raise ValueError(f"Nmap Annotator:: rule {row_number} has class without group")
        if os_type and not os_family:
            raise ValueError(f"Nmap Annotator:: rule {row_number} has os_type without os_family")
        if os_version and not os_type:
            raise ValueError(f"Nmap Annotator:: rule {row_number} has os_version without os_type")
        if group and not taxonomy.check_device(group, _class):
            raise ValueError(f"Nmap Annotator:: rule {row_number} has invalid device taxonomy")
        if os_family and not taxonomy.check_os(os_family, os_type, os_version):
            raise ValueError(f"Nmap Annotator:: rule {row_number} has invalid OS taxonomy")

    @staticmethod
    def load(db_file: str) -> dict:
        """Load mapping rules from the Nmap CSV database.

        Parameters
        ----------
        db_file : str
            Path to the CSV rule database.

        Returns
        -------
        dict
            Rules grouped by evidence source. Each rule contains a compiled pattern
            and a dictionary of validated output labels.

        Raises
        ------
        FileNotFoundError
            If the database file does not exist.
        ValueError
            If a header, source, regular expression, or taxonomy label is invalid.
        """

        db_path = Path(db_file)
        if not db_path.is_file():
            logger.error(f"Nmap Annotator:: rule database does not exist: {db_path}")
            raise FileNotFoundError(f"Nmap Annotator:: rule database does not exist: {db_path}")

        label_fields = ["group", "class", "os_family", "os_type", "os_version"]
        required_columns = ["source", "pattern"] + label_fields
        rules = {}

        with db_path.open("r", encoding="utf-8", newline="") as file:
            csv_reader = csv.DictReader(file)

            columns = csv_reader.fieldnames
            if columns is None or sorted(columns) != sorted(required_columns):
                raise ValueError(
                    f"Nmap Annotator:: rule database must have columns: {required_columns}"
                )

            for row_number, row in enumerate(csv_reader, start=2):
                source = row["source"].strip()
                if source not in RULE_SOURCES:
                    raise ValueError(f"Nmap Annotator:: rule {row_number} has unknown source: {source}")

                try:
                    pattern = re.compile(row["pattern"], re.IGNORECASE)
                except re.error as error:
                    raise ValueError(
                        f"Nmap Annotator:: rule {row_number} has invalid regular expression"
                    ) from error

                # Empty output cells leave that part of the annotation unknown.
                labels = {}
                for field in label_fields:
                    labels[field] = row[field].strip().lower() or None

                NmapRuleSet.validate_labels(labels, row_number)

                if source not in rules:
                    rules[source] = []

                rules[source].append({"pattern": pattern, "labels": labels})

        return rules

    @staticmethod
    def match_rules(values: list, rules: dict) -> list:
        """Apply source-specific rules, returning source names and expanded label dictionaries."""
        observations = []
        for source, value in values:
            if not value:
                continue
            for rule in rules.get(source, []):
                match = rule["pattern"].search(value)
                if match is None:
                    continue

                labels = {}
                for field, label in rule["labels"].items():
                    labels[field] = match.expand(label) if label else None
                observations.append({"source": source, "labels": labels})

        return observations


class NmapHostClassifier:
    """Translate the Nmap evidence of one host into a DAF annotation.

    Device labels prefer OS fingerprints and service device types over service roles,
    OS labels prefer fingerprints over service clues. Conflicting evidence leaves the
    affected labels unknown.

    Attributes
    ----------
    rule_set : NmapRuleSet
        Mapping rules.
    min_os_accuracy : float
        Minimal OS match accuracy (0-100).
    min_service_confidence : float
        Minimal service confidence (0-10).
    """

    def __init__(
        self, rule_set: NmapRuleSet, min_os_accuracy: float, min_service_confidence: float
    ) -> None:
        """Initialize the classifier, see the class attributes."""

        self.rule_set = rule_set
        self.min_os_accuracy = min_os_accuracy
        self.min_service_confidence = min_service_confidence

    @staticmethod
    def get_os_evidence(host: dict, min_accuracy: float) -> list:
        """Return (source, value) pairs from the best eligible OS fingerprints.

        Keep tied matches to expose conflicts. Fall back to direct OS classes for
        older reports without nested classes. Accuracy uses Nmap's 0–100 scale."""
        matches = [
            match
            for match in host["os_matches"]
            if float(match.get("accuracy", -1)) >= min_accuracy
        ]
        if matches:
            best_accuracy = max(float(match["accuracy"]) for match in matches)
            matches = [match for match in matches if float(match["accuracy"]) == best_accuracy]

        values = []
        for match in matches:
            values.append(("os_match_name", match.get("name")))
            for os_class in match["classes"]:
                class_accuracy = float(os_class.get("accuracy", match["accuracy"]))
                if class_accuracy >= min_accuracy:
                    values.extend(NmapHostClassifier.get_os_class_values(os_class))

        if matches and any(match["classes"] for match in matches):
            return values

        classes = [
            os_class
            for os_class in host["os_classes"]
            if float(os_class.get("accuracy", -1)) >= min_accuracy
        ]
        if classes:
            best_accuracy = max(float(os_class["accuracy"]) for os_class in classes)
            for os_class in classes:
                if float(os_class["accuracy"]) == best_accuracy:
                    values.extend(NmapHostClassifier.get_os_class_values(os_class))
        return values

    @staticmethod
    def get_os_class_values(os_class: dict) -> list:
        """Return (source, value) pairs for an OS class's family, device type, and CPEs."""
        values = [
            ("os_class_family", os_class.get("osfamily")),
            ("os_class_type", os_class.get("type")),
        ]
        values.extend(("os_class_cpe", cpe) for cpe in os_class.get("cpes", []))
        return values

    @staticmethod
    def get_service_evidence(host: dict, min_confidence: float) -> list:
        """Return (source, value) pairs from open ports with actively probed services.

        Service confidence uses Nmap's 0–10 scale; port-number lookups are excluded."""
        field_sources = {
            "name": "service_name",
            "product": "service_product",
            "version": "service_version",
            "extrainfo": "service_extra_info",
            "ostype": "service_os_type",
            "devicetype": "service_device_type",
        }
        values = []
        for port in host["ports"]:
            service = port["service"]
            if port["state"].get("state") != "open":
                continue
            if service.get("method") != "probed" or float(service.get("conf", -1)) < min_confidence:
                continue
            for field, source in field_sources.items():
                values.append((source, service.get(field)))
            values.extend(("service_cpe", cpe) for cpe in service.get("cpes", []))
        return values

    @staticmethod
    def get_label_values(matches: list, field: str) -> list:
        """Collect unique nonempty labels for a field, preserving their order."""
        values = []
        for match in matches:
            value = match["labels"][field]
            if value and value not in values:
                values.append(value)
        return values

    @staticmethod
    def get_matching_label(matches: list, field: str):
        """Return the agreed label, or None for missing or conflicting labels."""
        values = NmapHostClassifier.get_label_values(matches, field)
        if len(values) == 1:
            return values[0]
        return None

    @staticmethod
    def get_device_annotation(device_matches: list, service_matches: list) -> tuple:
        """Return group and class, preferring device evidence over service roles."""
        groups = NmapHostClassifier.get_label_values(device_matches, "group")
        if not groups:
            group = NmapHostClassifier.get_matching_label(service_matches, "group")
            _class = NmapHostClassifier.get_matching_label(service_matches, "class")
            return group, _class

        if len(groups) > 1:
            return None, None

        group = groups[0]
        _class = NmapHostClassifier.get_matching_label(device_matches, "class")
        if _class is None:
            # A service role can only fill the class within the chosen device group.
            matching_services = []
            for match in service_matches:
                if match["labels"]["group"] == group:
                    matching_services.append(match)
            _class = NmapHostClassifier.get_matching_label(matching_services, "class")

        return group, _class

    @staticmethod
    def get_os_annotation(fingerprint_matches: list, service_matches: list) -> tuple:
        """Return family, type, and release, preferring fingerprints over service clues.

        Only use evidence compatible with the chosen parents. Missing or conflicting
        parents leave child labels unknown."""
        os_labels = {"os_family": None, "os_type": None, "os_version": None}

        # Choose the family before the distribution, and the distribution before its release.
        for field in os_labels:
            values = NmapHostClassifier.get_label_values(fingerprint_matches, field)
            if not values:
                values = NmapHostClassifier.get_label_values(service_matches, field)

            # Missing or conflicting parents leave their child labels unknown too.
            if len(values) != 1:
                break

            chosen_label = values[0]
            os_labels[field] = chosen_label

            # Keep only evidence compatible with the label we just chose.
            compatible_fingerprints = []
            for match in fingerprint_matches:
                label = match["labels"][field]
                if label is None or label == chosen_label:
                    compatible_fingerprints.append(match)
            fingerprint_matches = compatible_fingerprints

            compatible_services = []
            for match in service_matches:
                label = match["labels"][field]
                if label is None or label == chosen_label:
                    compatible_services.append(match)
            service_matches = compatible_services

        return os_labels["os_family"], os_labels["os_type"], os_labels["os_version"]

    def classify(self, host: dict) -> tuple:
        """Translate host evidence into group, class, OS family, type, and version."""
        os_evidence = self.get_os_evidence(host, self.min_os_accuracy)
        service_evidence = self.get_service_evidence(host, self.min_service_confidence)

        fingerprint_matches = self.rule_set.match(os_evidence)
        service_matches = self.rule_set.match(service_evidence)

        # A printer's HTTP service should not turn it into a web server.
        device_matches = list(fingerprint_matches)
        service_roles = []
        for match in service_matches:
            if match["source"] == "service_device_type":
                device_matches.append(match)
            else:
                service_roles.append(match)

        group, _class = NmapHostClassifier.get_device_annotation(device_matches, service_roles)
        os_family, os_type, os_version = NmapHostClassifier.get_os_annotation(fingerprint_matches, service_matches)

        return group, _class, os_family, os_type, os_version


class NmapScanner:
    """Run Nmap on a list of targets and save its XML report.

    Nmap is started without a shell. Targets are passed in a temporary file
    (``-iL``) and the report is written by ``-oX``.

    Attributes
    ----------
    nmap_path : str
        Nmap executable.
    arguments : list
        Nmap options, see :data:`DEFAULT_ARGUMENTS`.
    timeout : float or None
        Maximal duration of the scan in seconds.
    privileged : bool
        Pass ``--privileged`` to Nmap and skip the root check, for Nmap with
        capabilities.
    dry_run : bool
        Only log the command, do not run Nmap.
    """

    def __init__(
        self,
        nmap_path: str = "nmap",
        arguments: Optional[List[str]] = None,
        timeout: Optional[float] = None,
        privileged: bool = False,
        dry_run: bool = False,
    ) -> None:
        """Initialize and validate the scanner.

        Parameters
        ----------
        nmap_path : str, optional
            Nmap executable, by default ``nmap``.
        arguments : list, optional
            Nmap options, by default :data:`DEFAULT_ARGUMENTS`.
        timeout : float, optional
            Maximal duration of the scan in seconds, unlimited by default.
        privileged : bool, optional
            Pass ``--privileged`` and skip the root check, by default False.
        dry_run : bool, optional
            Only log the command, by default False.

        Raises
        ------
        ValueError
            If the arguments are not a list of strings or contain options set by DAF.
        """

        arguments = list(DEFAULT_ARGUMENTS if arguments is None else arguments)
        if not all(isinstance(argument, str) for argument in arguments):
            raise ValueError("Nmap Annotator:: arguments must be a list of strings")
        reserved = sorted(RESERVED_OPTIONS.intersection(arguments))
        if reserved:
            raise ValueError(f"Nmap Annotator:: arguments must not contain {', '.join(reserved)}")
        if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
            raise ValueError("Nmap Annotator:: timeout must be a positive number of seconds")

        self.nmap_path = nmap_path
        self.arguments = arguments
        self.timeout = timeout
        self.privileged = privileged
        self.dry_run = dry_run

    def command(self, targets_file: str, output_xml: str) -> List[str]:
        """Build the Nmap command.

        Parameters
        ----------
        targets_file : str
            File with one target per line.
        output_xml : str
            Path of the XML report.

        Returns
        -------
        list
            Command as a list of arguments.
        """

        privileged = ["--privileged"] if self.privileged else []
        return [self.nmap_path, *self.arguments, *privileged, "-iL", targets_file, "-oX", output_xml]

    def check_privileges(self) -> None:
        """Fail early if the options need privileges DAF does not have.

        Raises
        ------
        PermissionError
            If a privileged option is used without root and without ``privileged``.
        """

        options = sorted(PRIVILEGED_OPTIONS.intersection(self.arguments))
        geteuid = getattr(os, "geteuid", None)
        if not options or self.privileged or geteuid is None or geteuid() == 0:
            return
        raise PermissionError(
            f"Nmap Annotator:: options {', '.join(options)} require root privileges. Run DAF "
            "as root, set privileged: true for Nmap with capabilities, or use e.g. -sT "
            "without -O."
        )

    def scan(self, targets: List[str], output_xml: str) -> bool:
        """Scan the targets and write the XML report.

        Parameters
        ----------
        targets : list
            IP addresses, networks or host names accepted by Nmap.
        output_xml : str
            Path of the XML report.

        Returns
        -------
        bool
            True if the report was written, False in the dry run.

        Raises
        ------
        FileNotFoundError
            If the Nmap executable is not found.
        PermissionError
            If the options need missing privileges.
        RuntimeError
            If Nmap fails or exceeds the timeout.
        """

        nmap = shutil.which(self.nmap_path)
        if nmap is None and not self.dry_run:
            raise FileNotFoundError(f"Nmap Annotator:: Nmap executable not found: {self.nmap_path}")
        self.check_privileges()

        Path(output_xml).parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", prefix="daf_nmap_", delete=False) as file:
            file.write("\n".join(targets) + "\n")
            targets_file = file.name

        try:
            command = self.command(targets_file, output_xml)
            command[0] = nmap or self.nmap_path
            logger.info(f"    -- Nmap scan of {len(targets)} targets: {' '.join(command)}")
            if self.dry_run:
                logger.info("    -- Nmap dry run, scan not started")
                return False
            try:
                result = subprocess.run(
                    command,
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(
                    f"Nmap Annotator:: scan exceeded the timeout of {self.timeout} s"
                ) from error
        finally:
            Path(targets_file).unlink(missing_ok=True)

        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"Nmap Annotator:: Nmap failed ({result.returncode}): {message}")
        logger.info(f"    -- Nmap report saved to {output_xml}")
        return True


class NmapTargets:
    """Targets of an active Nmap scan configured as IP addresses and networks.

    Attributes
    ----------
    addresses : list
        IP address strings of all configured targets.
    """

    def __init__(self, targets: list) -> None:
        """Expand the configured targets.

        Parameters
        ----------
        targets : list
            IP addresses and networks in CIDR notation.
        """

        self.addresses = self.expand(targets)

    @staticmethod
    def expand(targets: list) -> List[str]:
        """Expand configured targets to the IP addresses they contain.

        Parameters
        ----------
        targets : list
            IP addresses and networks in CIDR notation.

        Returns
        -------
        list
            IP address strings.

        Raises
        ------
        ValueError
            If a target is not an IP address or network, or a network is too large.
        """

        addresses = []
        for target in targets:
            try:
                network = ipaddress.ip_network(str(target), strict=False)
            except ValueError as error:
                raise ValueError(f"Nmap Annotator:: invalid target: {target}") from error
            if network.num_addresses > MAX_TARGET_HOSTS:
                raise ValueError(
                    f"Nmap Annotator:: target {target} has more than {MAX_TARGET_HOSTS} addresses"
                )
            hosts = [network.network_address] if network.num_addresses == 1 else network.hosts()
            addresses.extend(str(address) for address in hosts)
        return addresses


class NmapAnnotator(IPAnnotator, IPSource):
    """Annotate IP addresses from an Nmap XML report.

    The annotator works in one of two modes (``mode``):

    - ``passive`` (default): a completed report (``xml_file``) is imported. As an
      :class:`IPSource`, the annotator adds the IPs of the report, so it can run
      without a dataset.
    - ``active``: DAF runs Nmap itself (:class:`NmapScanner`). The annotated IPs
      (if ``scan_dataset_ips``) except IPs flagged as multi-devices, and the
      configured ``targets`` are scanned in one Nmap run. The module is deferred, so
      the scan starts after the detectors have flagged multi-devices. The configured
      targets are added to the annotated IPs.

    The parsed evidence is stored under ``IP.data["nmap_annotator"]`` of every IP found
    in the report and at most one annotation per host is created from the rule database.

    Attributes
    ----------
    mode : str
        ``passive`` or ``active``.
    scanner : NmapScanner or None
        Scanner of the active mode.
    targets : NmapTargets or None
        Configured targets of the active mode.
    evidence_by_ip : dict
        Parsed evidence keyed by IP address string.
    classifier : NmapHostClassifier
        Translation of host evidence into annotations.
    """

    name = "nmap_annotator"
    description = "Nmap annotation"
    REQUIREMENTS = (
        Requirement("mode", str, default="passive", choices=MODES),
        Requirement("xml_file", str, required_if={"mode": "passive"}),
        Requirement("db_file", str),
        Requirement("min_os_accuracy", (int, float), minimum=0, maximum=100),
        Requirement("min_service_confidence", (int, float), minimum=0, maximum=10),
        Requirement("nmap_path", str, default="nmap"),
        Requirement("arguments", list, required=False),
        Requirement("targets", (list, tuple), default=()),
        Requirement("scan_dataset_ips", bool, default=True),
        Requirement("output_xml", str, default="nmap_active_scan.xml"),
        Requirement("timeout", (int, float), required=False),
        Requirement("privileged", bool, default=False),
        Requirement("dry_run", bool, default=False),
    )

    def __init__(self, config: dict) -> None:
        """Check the configuration and prepare the scanner of the active mode.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.

        Raises
        ------
        ValueError
            If a scanner setting or a target is invalid.
        """

        super().__init__(config)
        self.mode = self.config["mode"]
        self.scanner = None
        self.targets = None
        if self.mode == "active":
            self.scanner = NmapScanner(
                nmap_path=self.config["nmap_path"],
                arguments=self.config.get("arguments"),
                timeout=self.config.get("timeout"),
                privileged=self.config["privileged"],
                dry_run=self.config["dry_run"],
            )
            self.targets = NmapTargets(list(self.config["targets"]))
        self.evidence_by_ip = {}

    @property
    def deferred(self) -> bool:
        """Run the active scan after the other modules flagged multi-devices."""

        return self.mode == "active"

    @property
    def output_xml(self) -> str:
        """Return the path of the report written in the active mode."""

        return str(Path(self.config["output_xml"]).resolve())

    @property
    def xml_path(self) -> str:
        """Return the absolute path to the XML report of the mode."""

        if self.mode == "active":
            return self.output_xml
        return str(Path(self.config["xml_file"]).resolve())

    def setup(self) -> None:
        """Load the rule database and, in the passive mode, parse the XML report."""

        self.classifier = NmapHostClassifier(
            NmapRuleSet(self.config["db_file"]),
            self.config["min_os_accuracy"],
            self.config["min_service_confidence"],
        )
        if self.mode == "passive":
            self.evidence_by_ip = NmapReportParser.parse(self.xml_path)

    def provide_ips(self) -> tuple:
        """Provide the source name and IP objects of the module's input.

        Returns
        -------
        tuple
            Absolute XML report path and new IP objects: the hosts of the report in
            the passive mode, the configured targets in the active mode.
        """

        self.ensure_setup()
        if self.mode == "active":
            return self.xml_path, [IP(ip_addr) for ip_addr in self.targets.addresses]
        return self.xml_path, [IP(ip_addr) for ip_addr in self.evidence_by_ip]

    def select_scan_targets(self, ip_addresses: list) -> List[str]:
        """Select the targets of the active scan.

        Parameters
        ----------
        ip_addresses : list
            IP objects annotated in this run.

        Returns
        -------
        list
            IP address strings without duplicates. IPs flagged as multi-devices are
            not scanned.
        """

        targets = []
        if self.config["scan_dataset_ips"]:
            targets.extend(str(ip.ip_addr) for ip in ip_addresses)
        else:
            requested = set(self.targets.addresses)
            targets.extend(str(ip.ip_addr) for ip in ip_addresses if str(ip.ip_addr) in requested)
        flagged = {str(ip.ip_addr) for ip in ip_addresses if ip.multi_device}
        if flagged:
            logger.info(f"    -- {len(flagged)} multi-device IPs are not scanned")
        return [target for target in dict.fromkeys(targets) if target not in flagged]

    def before_run(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Run the active scan of this run's IPs and parse its report.

        Parameters
        ----------
        ip_addresses : list
            IP objects annotated in this run.
        flows_by_ip : dict
            Not used.
        """

        if self.mode != "active":
            return
        targets = self.select_scan_targets(ip_addresses)
        if not targets:
            logger.info("    -- no IPs to scan")
            self.evidence_by_ip = {}
            return
        if self.scanner.scan(targets, self.output_xml):
            self.evidence_by_ip = NmapReportParser.parse(self.output_xml)
        else:
            self.evidence_by_ip = {}

    def annotate_ip(self, ip) -> None:
        """Translate the Nmap evidence of one IP into an annotation.

        Parameters
        ----------
        ip : IP
            IP object to annotate. IPs missing in the report are skipped.
        """

        evidence = self.evidence_by_ip.get(str(ip.ip_addr))
        if evidence is None:
            return
        ip.add_data("nmap_annotator", evidence)
        if evidence["host"]["status"].get("state") == "up":
            annotation = Annotation(*self.classifier.classify(evidence["host"]))
            if not annotation.is_empty():
                ip.add_annotation("nmap_annotator", annotation)
