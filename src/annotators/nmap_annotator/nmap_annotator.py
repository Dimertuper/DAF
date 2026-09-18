#!/usr/bin/python3
"""
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: nmap_annotator.py
Description: Annotate DAF IP objects from a previously generated Nmap XML report.
"""

import csv
import ipaddress
import logging
import re
from pathlib import Path
from xml.etree import ElementTree

from ip import IP, Annotation

logger = logging.getLogger("Nmap Annotator")

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


def check_config(config: dict) -> dict:
    """Validate required settings and the OS (0–100) and service (0–10) thresholds."""
    if "nmap_annotator" not in config:
        logger.error("Nmap annotator configuration not found in configuration file")
        raise RuntimeError("Nmap Annotator:: configuration is missing")
    local_config = config["nmap_annotator"]
    required = ("xml_file", "db_file", "min_os_accuracy", "min_service_confidence")
    missing = [key for key in required if key not in local_config]
    if missing:
        logger.error(f"Nmap Annotator:: missing configuration: {', '.join(missing)}")
        raise RuntimeError(f"Nmap Annotator:: missing configuration: {', '.join(missing)}")

    os_accuracy = local_config["min_os_accuracy"]
    service_confidence = local_config["min_service_confidence"]
    if not isinstance(os_accuracy, (int, float)) or not 0 <= os_accuracy <= 100:
        raise ValueError("Nmap Annotator:: min_os_accuracy must be between 0 and 100")
    if not isinstance(service_confidence, (int, float)) or not 0 <= service_confidence <= 10:
        raise ValueError("Nmap Annotator:: min_service_confidence must be between 0 and 10")
    return local_config


def get_xml_attributes(element) -> dict:
    """Return an element's attributes, or an empty dictionary if it is absent."""
    return dict(element.attrib) if element is not None else {}


def parse_cpe_element(element) -> dict:
    """Read attributes and CPE identifiers from a service or OS class."""
    if element is None:
        return {}
    result = get_xml_attributes(element)
    result["cpes"] = [cpe.text.strip() for cpe in element.findall("cpe") if cpe.text]
    return result


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
    scan["finished"] = get_xml_attributes(finished)
    return scan


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


def parse_ports(host) -> list:
    """Read each port's protocol, number, state, and detected service."""
    ports = []
    for port in host.findall("./ports/port"):
        port_data = {
            "protocol": port.get("protocol"),
            "port": int(port.get("portid")),
            "state": get_xml_attributes(port.find("state")),
            "service": parse_cpe_element(port.find("service")),
        }
        ports.append(port_data)
    return ports


def parse_os_matches(host) -> list:
    """Read OS fingerprints and their nested classes."""
    matches = []
    for os_match in host.findall("./os/osmatch"):
        match_data = get_xml_attributes(os_match)
        match_data["classes"] = []
        for os_class in os_match.findall("osclass"):
            match_data["classes"].append(parse_cpe_element(os_class))
        matches.append(match_data)
    return matches


def parse_host(host) -> dict:
    """Collect host timestamps, status, addresses, names, OS evidence, and ports."""
    addresses = []
    for address in host.findall("address"):
        addresses.append(get_xml_attributes(address))

    hostnames = []
    for hostname in host.findall("./hostnames/hostname"):
        hostnames.append(get_xml_attributes(hostname))

    # Older reports put classes directly under os; newer reports nest them in matches.
    os_classes = []
    for os_class in host.findall("./os//osclass"):
        os_classes.append(parse_cpe_element(os_class))

    return {
        "starttime": host.get("starttime"),
        "endtime": host.get("endtime"),
        "status": get_xml_attributes(host.find("status")),
        "addresses": addresses,
        "hostnames": hostnames,
        "os_matches": parse_os_matches(host),
        "os_classes": os_classes,
        "ports": parse_ports(host),
    }


def parse_nmap_xml(xml_file: str) -> dict:
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

    scan = parse_scan(root)
    evidence_by_ip = {}

    for host in root.findall("host"):
        ip_addresses = get_host_ips(host)
        if not ip_addresses:
            continue

        evidence = {"scan": scan, "host": parse_host(host)}
        for ip_addr in ip_addresses:
            evidence_by_ip[ip_addr] = evidence

    return evidence_by_ip


def provide_ips(config: dict) -> tuple:
    """Provide the source name and IP objects represented by the Nmap report.

    Parameters
    ----------
    config : dict
        Complete DAF configuration containing the ``nmap_annotator`` section.

    Returns
    -------
    tuple
        Absolute XML source path and IP objects with their Nmap evidence attached.
        The annotation step reads this evidence from each object.
    """

    local_config = check_config(config)
    path = str(Path(local_config["xml_file"]).resolve())
    evidence_by_ip = parse_nmap_xml(path)

    ip_addresses = []
    for ip_addr, evidence in evidence_by_ip.items():
        ip = IP(ip_addr)
        ip.add_data("nmap_annotator", evidence)
        ip_addresses.append(ip)

    return path, ip_addresses


def validate_rule_labels(labels: dict, row_number: int) -> None:
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


def load_rules(db_file: str) -> dict:
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

            validate_rule_labels(labels, row_number)

            if source not in rules:
                rules[source] = []

            rules[source].append({"pattern": pattern, "labels": labels})

    return rules


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
                values.extend(get_os_class_values(os_class))

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
                values.extend(get_os_class_values(os_class))
    return values


def get_os_class_values(os_class: dict) -> list:
    """Return (source, value) pairs for an OS class's family, device type, and CPEs."""
    values = [
        ("os_class_family", os_class.get("osfamily")),
        ("os_class_type", os_class.get("type")),
    ]
    values.extend(("os_class_cpe", cpe) for cpe in os_class.get("cpes", []))
    return values


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


def get_label_values(matches: list, field: str) -> list:
    """Collect unique nonempty labels for a field, preserving their order."""
    values = []
    for match in matches:
        value = match["labels"][field]
        if value and value not in values:
            values.append(value)
    return values


def get_matching_label(matches: list, field: str):
    """Return the agreed label, or None for missing or conflicting labels."""
    values = get_label_values(matches, field)
    if len(values) == 1:
        return values[0]
    return None


def get_device_annotation(device_matches: list, service_matches: list) -> tuple:
    """Return group and class, preferring device evidence over service roles."""
    groups = get_label_values(device_matches, "group")
    if not groups:
        group = get_matching_label(service_matches, "group")
        _class = get_matching_label(service_matches, "class")
        return group, _class

    if len(groups) > 1:
        return None, None

    group = groups[0]
    _class = get_matching_label(device_matches, "class")
    if _class is None:
        # A service role can only fill the class within the chosen device group.
        matching_services = []
        for match in service_matches:
            if match["labels"]["group"] == group:
                matching_services.append(match)
        _class = get_matching_label(matching_services, "class")

    return group, _class


def get_os_annotation(fingerprint_matches: list, service_matches: list) -> tuple:
    """Return family, type, and release, preferring fingerprints over service clues.

    Only use evidence compatible with the chosen parents. Missing or conflicting
    parents leave child labels unknown."""
    os_labels = {"os_family": None, "os_type": None, "os_version": None}

    # Choose the family before the distribution, and the distribution before its release.
    for field in os_labels:
        values = get_label_values(fingerprint_matches, field)
        if not values:
            values = get_label_values(service_matches, field)

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


def get_annotation_based_on_nmap(host: dict, rules: dict, config: dict) -> tuple:
    """Translate host evidence into group, class, OS family, type, and version."""
    os_evidence = get_os_evidence(host, config["min_os_accuracy"])
    service_evidence = get_service_evidence(host, config["min_service_confidence"])

    fingerprint_matches = match_rules(os_evidence, rules)
    service_matches = match_rules(service_evidence, rules)

    # A printer's HTTP service should not turn it into a web server.
    device_matches = list(fingerprint_matches)
    service_roles = []
    for match in service_matches:
        if match["source"] == "service_device_type":
            device_matches.append(match)
        else:
            service_roles.append(match)

    group, _class = get_device_annotation(device_matches, service_roles)
    os_family, os_type, os_version = get_os_annotation(fingerprint_matches, service_matches)

    return group, _class, os_family, os_type, os_version


def annotate(ip_addresses: list, config: dict, ip_data_dict=None) -> None:
    """Translate the Nmap evidence attached to each IP into an annotation.

    Parameters
    ----------
    ip_addresses : list
        DAF IP objects from the flow/XML union. Objects supplied by provide_ips
        carry their parsed evidence under IP.data["nmap_annotator"].
    config : dict
        Complete DAF configuration containing thresholds and the rule database path.
    ip_data_dict : dict, optional
        Flow data supplied by DAF. Nmap does not use it because its evidence comes
        from the XML report.

    Returns
    -------
    None
        Evidence is stored under ``IP.data["nmap_annotator"]`` and at most one
        annotation is stored under ``IP.annotations["nmap_annotator"]``.
    """

    local_config = check_config(config)
    rules = load_rules(local_config["db_file"])
    total_ips = len(ip_addresses)
    log_interval = max(1, total_ips // 10)

    for cnt_ip, ip in enumerate(ip_addresses, start=1):
        if config["daf"]["progress_print"] and (cnt_ip % log_interval == 0 or cnt_ip == total_ips):
            progress = (cnt_ip / total_ips) * 100
            logger.info(f"    -- Nmap annotation ... {progress:.0f} %")

        evidence = ip.data.get("nmap_annotator")
        if evidence is None:
            continue
        if evidence["host"]["status"].get("state") == "up":
            labels = get_annotation_based_on_nmap(evidence["host"], rules, local_config)
            annotation = Annotation(*labels)
            if not annotation.is_empty():
                ip.add_annotation("nmap_annotator", annotation)

    logger.info("    -- Nmap annotation ... DONE")
