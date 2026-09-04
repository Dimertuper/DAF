#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: ip.py
Description: Defines the IP class for representing and annotating IP addresses,
including methods for merging annotations, exporting/importing data, and handling annotation conflicts.
"""

import ipaddress
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator, TypeVar, Union

from annotation import Annotation

TIP = TypeVar("TIP", bound="IP")

logger = logging.getLogger("IP")


class IP:
    """Represents an IP address.

    This class provides methods to initialize an IP instance, compare IP objects,
    update an instance with annotations and data from another instance, add annotations
    and data to an IP, perform annotation by merging annotations, and retrieve the final annotation.

    Attributes
    ----------
    ip_addr : ipaddress.IPv4Address or ipaddress.IPv6Address
        The IP address assigned to the instance.
    final_annotation : Annotation
        The final annotation of the IP.
    annotations : dict
        A dictionary containing annotations added to the IP.
    data : dict
        A dictionary containing data added to the IP.
    hand_miss : list
        A list of cases where hand annotator tag is different from the final annotation.
    one_miss : list
        A list cases where final annotation was aborted due to one different tag.
    multi_device : list
        A list cases where annotator created multiple different annotations.
        Possibly due to multiple devices hiding behind one IP.
    """

    def __init__(self: TIP, ip_addr: str) -> None:
        """Initialize a new instance of the IP class.

        Parameters
        ----------
        self : TIP
            The IP instance itself.
        ip_addr : str
            The IP address to be assigned to the instance.

        Returns
        -------
        None
        """

        self.ip_addr = ipaddress.ip_address(ip_addr)
        self.final_annotation = Annotation()
        self.annotations = {}
        self.data = {}

        self.hand_miss = []
        self.one_miss = []
        self.multi_device = []

    def __eq__(self: TIP, other: Any) -> bool:
        """Check if the IP object is equal to another object.

        Parameters
        ----------
        self : TIP
            The IP object.
        other : Any
            The object to compare with.

        Returns
        -------
        bool
            True if the IP object is equal to the other object, False otherwise.
        """

        if isinstance(other, IP):
            return self.ip_addr == other.ip_addr
        return self.ip_addr == other

    def __iadd__(self: TIP, other: TIP) -> TIP:
        """Update the current instance with the annotations, data, and other attributes from another instance.

        Parameters
        ----------
        self : TIP
            The current instance.
        other : TIP
            The instance to be added.

        Returns
        -------
        TIP
            The updated instance.
        """

        for key in self.annotations.keys():
            if key in other.annotations:
                logger.warning(f"Encountered multiple keys, while updating annotation: {key}")
        for key in self.data.keys():
            if key in other.data:
                logger.warning(f"Encountered multiple keys, while updating data: {key}")

        self.annotations.update(other.annotations)
        self.data.update(other.data)

        self.hand_miss.extend(other.hand_miss)
        self.one_miss.extend(other.one_miss)
        self.multi_device.extend(other.multi_device)

        return self

    def add_annotation(self: TIP, annotator_name: str, annotation: Annotation) -> None:
        """Add an annotation to the IP.

        Parameters
        ----------
        self : TIP
            The current instance of the IP.
        annotator_name : str
            The name of the annotator who created the annotation.
        annotation : Annotation
            The annotation to be added.
        """

        if annotator_name in self.annotations:
            logger.warning(f"Duplicate annotation added to IP, source: {annotator_name}")
        self.annotations[annotator_name] = annotation

    def add_data(self: TIP, annotator_name: str, data: Any) -> None:
        """Add data to the IP.

        This method adds data to the IP object. If the annotator name already exists in the IP's data,
        a warning message is logged.

        Parameters
        ----------
        self : TIP
            The IP object.
        annotator_name : str
            The name of the annotator.
        data : Any
            The data to be added.
        """

        if annotator_name in self.data:
            logger.warning(f"Duplicate data added to IP, source: {annotator_name}")
        self.data[annotator_name] = data

    def perform_annotation(self: TIP, min_annotators_count: int) -> None:
        """Perform annotation by merging annotations and updating final annotation.

        This method merges the annotations from different annotators and updates the final annotation
        based on the merged values. If a hand annotator is present, its values will be used for the
        final annotation.

        Parameters
        ----------
        self : TIP
            The instance of the TIP class.
        min_annotators_count : int
            The minimum number of annotators required for merging annotations.
        """

        # Merge annotations
        group = self.merge_annotation(
            [x.group for x in self.annotations.values()], min_annotators_count
        )
        _class = self.merge_annotation(
            [x._class for x in self.annotations.values()], min_annotators_count, False
        )
        os_family = self.merge_annotation(
            [x.os_family for x in self.annotations.values()], min_annotators_count
        )
        os_type = self.merge_annotation(
            [x.os_type for x in self.annotations.values()], min_annotators_count
        )
        os_version = self.merge_annotation(
            [x.os_version for x in self.annotations.values()],
            min_annotators_count,
            False,
        )

        self.final_annotation.set_annotation(group, _class, os_family, os_type, os_version)

        # If hand annotator is present, use its values
        if "hand_annotator" in self.annotations:
            for attr_name in ["group", "_class", "os_family", "os_type", "os_version"]:
                hand_value = getattr(self.annotations["hand_annotator"], attr_name, None)
                final_value = getattr(self.final_annotation, attr_name, None)

                if hand_value and hand_value != final_value:
                    self.hand_miss.append([attr_name, hand_value, final_value])
                    setattr(self.final_annotation, attr_name, hand_value)

    def merge_annotation(
        self: TIP,
        tags: list,
        min_annotators_count: int,
        nat_check: bool = True,
    ) -> str:
        """Merge the annotations based on the given tags and minimum annotators count.
        The function takes in multiple annotation parameters and returns a merged
        annotation if there is only one non-null value, otherwise it returns an empty string.

        Parameters
        ----------
        self : TIP
            The instance of the TIP class.
        tags : list
            The list of tags representing the annotations.
        min_annotators_count : int
            The minimum number of annotators required for a tag to be considered valid.
        nat_check : bool, optional
            A flag indicating whether to perform NAT check (default is True).

        Returns
        -------
        str
            The merged annotation tag.
        """

        # Filter None or empty tags
        tags = [tag for tag in tags if tag]
        count = Counter(tags).most_common()

        if len(count) == 0:
            return ""
        # Only one tag with count higher than minimum
        if len(count) == 1 and count[0][1] >= min_annotators_count:
            return count[0][0]
        # most tags are same(count higher than minimum), one is wrong
        if len(count) == 2 and count[0][1] >= min_annotators_count and count[-1][1] == 1:
            self.one_miss.append(count)
            return ""

        if nat_check and len(count) > 1:
            self.multi_device.append(["IP:merge_annotation_fail", tags])

        return ""

    def ret_annotation(self: TIP) -> list:
        """Return the final annotation.

        Parameters
        ----------
        self : TIP
            The current instance of the TIP class.

        Returns
        -------
        list
            The annotation.

        """
        return self.final_annotation.ret_annotation()

    def export(self) -> dict:
        """Export the IP object as a dictionary for JSON serialization.

        Returns
        -------
        dict
            The IP object as a dictionary, suitable for JSON serialization.
        """

        return {
            "ip_addr": str(self.ip_addr),
            "final_annotation": self.final_annotation.export(),
            "annotations": {key: value.export() for key, value in self.annotations.items()},
            "data": self.data,
            "hand_miss": self.hand_miss,
            "one_miss": self.one_miss,
            "multi_device": self.multi_device,
        }

    @classmethod
    def load(cls, data: dict) -> TIP:
        """Load the IP object from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary representing the IP object.
            It should contain keys "ip_addr", "final_annotation", "annotations",
            "data", "hand_miss", "one_miss", and "multi_device".

        Returns
        -------
        TIP
            The created instance of the IP class.
        """

        loaded_ip = cls(data["ip_addr"])
        loaded_ip.final_annotation = Annotation.load(data["final_annotation"])
        loaded_ip.annotations = {
            name: Annotation.load(anno) for name, anno in data.get("annotations", {}).items()
        }
        loaded_ip.data = data.get("data", {})
        loaded_ip.hand_miss = data.get("hand_miss", [])
        loaded_ip.one_miss = data.get("one_miss", [])
        loaded_ip.multi_device = data.get("multi_device", [])

        return loaded_ip


class IPCollection:
    """Ordered collection of IP objects without duplicate addresses.

    When an address is added more than once, the first object is kept, so e.g. saved
    reannotation objects win over newly created ones.

    Attributes
    ----------
    ips : dict
        IP objects keyed by IP address string, in insertion order.
    """

    def __init__(self, *ip_lists: Iterable) -> None:
        """Create the collection from lists of IP objects.

        Parameters
        ----------
        *ip_lists : Iterable
            Ordered iterables of :class:`IP` objects.
        """

        self.ips = {}
        for ip_list in ip_lists:
            self.extend(ip_list)

    def add(self, ip: IP) -> bool:
        """Add an IP object unless its address is already present.

        Parameters
        ----------
        ip : IP
            IP object.

        Returns
        -------
        bool
            True if the object was added.
        """

        key = str(ip.ip_addr)
        if key in self.ips:
            return False
        self.ips[key] = ip
        return True

    def extend(self, ip_list: Iterable) -> None:
        """Add IP objects whose addresses are not present yet.

        Parameters
        ----------
        ip_list : Iterable
            IP objects.
        """

        for ip in ip_list:
            self.add(ip)

    def keys(self) -> set:
        """Return the IP address strings of the collection."""

        return set(self.ips)

    def __contains__(self, ip_addr: object) -> bool:
        """Return whether an address (string or IP object) is in the collection."""

        return str(ip_addr.ip_addr if isinstance(ip_addr, IP) else ip_addr) in self.ips

    def __iter__(self) -> Iterator[IP]:
        """Iterate over the IP objects in insertion order."""

        return iter(self.ips.values())

    def __len__(self) -> int:
        """Return the number of IP objects."""

        return len(self.ips)

    def to_list(self) -> list:
        """Return the IP objects as a list."""

        return list(self.ips.values())


class IPDataFile:
    """JSON file with the complete state of annotated IP addresses.

    Attributes
    ----------
    path : pathlib.Path
        Path to the JSON file.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        """Initialize the file.

        Parameters
        ----------
        path : str or pathlib.Path
            Path to the JSON file.
        """

        self.path = Path(path)

    def save(self, ip_addresses: Iterable) -> None:
        """Export IP objects to the file.

        Parameters
        ----------
        ip_addresses : Iterable
            IP objects to export.
        """

        export_data = [ip.export() for ip in ip_addresses]
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=4)

    def load(self) -> list:
        """Load IP objects from the file.

        Returns
        -------
        list
            Loaded IP objects.

        Raises
        ------
        ValueError
            If the file does not exist.
        """

        if not self.path.is_file():
            logger.error("load_ip_data: path to reannotation file is not specified or incorrect")
            raise ValueError("load_ip_data: path to reannotation file is not specified or incorrect")

        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return [IP.load(item) for item in data]
