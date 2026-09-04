#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: useragent_annotator.py
Description: Useragent annotator module used to annotate IP addresses with useragent-based metadata.
"""

import logging
from collections import Counter

from annotation import Annotation
from config import Requirement
from core import DAFModule

from . import translate_useragent as translate

logger = logging.getLogger("Useragent Annotator")


class UserAgentClassifier:
    """Translation of HTTP useragents to DAF annotations.

    Useragents are translated by :class:`translate_useragent.HTTP_useragent`; the
    methods of this class combine the translated useragents of one IP address into
    one annotation and detect conflicting operating systems.
    """

    @staticmethod
    def most_common(lst: list) -> str:
        """Function used to get most common element from list.

        Parameters
        ----------
        lst : list
            List of elements to get most common from.

        Returns
        -------
        str
            Most common element from list.
        """

        if len(lst) == 0:
            return None
        counter = Counter(lst).most_common()

        return counter[0][0]

    @staticmethod
    def separate_os_info(os: str) -> list:
        """Function used to separate OS info from string.
        Outpout of http_useragent module is one string with OS info, this function is used to separate it into family, type and version.

        Parameters
        ----------
        os : str
            String with OS info.

        Returns
        -------
        list
            List with separated OS info: family, type, version.
        """

        family = type = version = None
        s = os.lower().split(sep=" ")

        # All with one word
        if len(s) == 1:
            family = s[0]
        # Windows
        elif s[0] == "windows":
            family = "windows"
            if len(s) == 2:
                if s[1].replace(".", "").isnumeric() or s[1] == "vista" or s[1] == "xp":
                    version = s[1]
                    type = "windows"
                else:
                    type = s[1]
            if len(s) > 2:
                if s[-1].replace(".", "").isnumeric():
                    version = s[-1]
                    type = " ".join(s[1:-1])
                else:
                    type = " ".join(s[1:])
        # Android
        elif os.find("android") != -1 or os.find("redmi") != -1:
            family = "android"
            type = "android"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Mac OS X
        elif os.find("mac") != -1 or os.find("apple") != -1:
            family = "macos"
            type = "macos"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Apple iPadOS
        elif os.find("ipad") != -1:
            family = "macos"
            type = "ipados"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # iPhone iOS
        elif os.find("ios") != -1 or os.find("iphone") != -1:
            family = "macos"
            type = "ios"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Fedora
        elif os.find("fedora") != -1:
            family = "linux"
            type = "fedora"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Debian
        elif os.find("debian") != -1:
            family = "linux"
            type = "debian"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Ubuntu
        elif os.find("ubuntu") != -1:
            family = "linux"
            type = "ubuntu"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # FreeBSD
        elif os.find("freebsd") != -1:
            family = "unix"
            type = "freebsd"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Random linux distros: linux mint
        elif s[0] == "linux":
            family = "linux"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
                type = " ".join(s[1:-1])
            else:
                type = " ".join(s[1:])
        # Chrome OS
        elif os.find("chrome") != -1:
            family = "linux"
            type = "chromeos"
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
        # Rest of the world
        else:
            family = s[0]
            if s[-1].replace(".", "").isnumeric():
                version = s[-1]
                type = " ".join(s[1:-1])
            else:
                type = " ".join(s[1:])

        return [family, type, version]

    @staticmethod
    def parse_tags(http_useragents: list, min_annotation_count: int) -> list:
        """Function used to parse tags from HTTP_useragent class.

        Parameters
        ----------
        http_useragents : list[HTTP_useragent]
            List of HTTP_useragent classes.
        min_annotation_count : int
            Minimal number of annotated samples, needed to assign label.

        Returns
        -------
        list
            List with parsed tags: family, type, version, hardware type, hardware sub type.
        """

        t_family = []
        t_type = []
        t_version = []
        t_hw_type = []
        t_hw_sub_type = []
        nat = []

        # Parse tags from http_useragent module
        for agent in http_useragents.values():
            for key, tag in agent.tags.items():
                if key == "operating_system":
                    f, t, v = UserAgentClassifier.separate_os_info(tag)
                    t_family.append(f)
                    t_type.append(t)
                    t_version.append(v)
                if key == "hardware_type":
                    t_hw_type.append(tag)
                if key == "harware_sub_type":
                    t_hw_sub_type.append(tag)

        # Delete *OS* from OS names
        for i in range(len(t_family)):
            t_family[i] = t_family[i].replace("*", "")
        for i in range(len(t_type)):
            t_type[i] = t_type[i].replace("*", "")
        for i in range(len(t_version)):
            t_version[i] = t_version[i].replace("*", "")

        # NAT check
        if len(set(t_family)) > 1:
            nat = t_family.copy()

        if len(t_family) < min_annotation_count:
            return [None, None, None, None, None, nat]

        t_family = UserAgentClassifier.most_common(t_family)
        t_type = UserAgentClassifier.most_common(t_type)
        t_version = UserAgentClassifier.most_common(t_version)

        t_hw_type = UserAgentClassifier.most_common(t_hw_type)
        t_hw_sub_type = UserAgentClassifier.most_common(t_hw_sub_type)

        return [t_family, t_type, t_version, t_hw_type, t_hw_sub_type, nat]

    @staticmethod
    def annotation_from_useragents(
        http_useragents: list, min_annotation_count: int
    ) -> list:
        """Function used to get annotation based on HTTP_useragents for single IP.

        Parameters
        ----------
        http_useragents : list[HTTP_useragent]
            List of HTTP_useragent classes for IP.
        min_annotation_count : int
            Minimal number of annotated samples, needed to assign label.

        Returns
        -------
        list
            List with annotation: group, class, family, type, version.


        Raises
        ------
        ValueError
            Raised whend HTTP_useragent os format is not valid.
        """

        group = _class = os_family = os_type = os_version = None

        # OS_family
        os_list = []
        mine_os_list = []
        multi_flag = []

        # Collects possible OS from different useragent
        for agent in http_useragents.values():
            if isinstance(agent.os, str):
                if agent.os is not None and agent.os != "":
                    os_list.append(agent.os)
            elif isinstance(agent.os, list):
                for o in agent.os:
                    if o is not None and o != "":
                        os_list.append(o)
            else:
                raise ValueError("Something wrong with HTTP_useragent os format")

            if agent.mine_os is not None and agent.mine_os != "":
                mine_os_list.append(agent.mine_os)

        # Delete *OS* from OS names
        for i in range(len(os_list)):
            os_list[i] = os_list[i].replace("*", "")

        # Check for multiple OS in os list
        if len(set(os_list)) > 1:
            families = []
            for i in range(len(os_list)):
                tmp_family, _, _ = UserAgentClassifier.separate_os_info(os_list[i])
                families.append(tmp_family)
            if len(set(families)) > 1:
                multi_flag.append(list(set(os_list)))

        # Select most common OS
        os_list_len = len(os_list)
        if os_list_len != 0 and os_list_len >= min_annotation_count:
            os_family = UserAgentClassifier.most_common(os_list)
            os_family, os_type, os_version = UserAgentClassifier.separate_os_info(os_family)

        # Get info from tags
        t_family, t_type, t_version, t_hw_type, t_hw_sub_type, tags_nat = UserAgentClassifier.parse_tags(
            http_useragents, min_annotation_count
        )

        # Check for multiple OS in tags
        if len(tags_nat) > 0:
            multi_flag.append(list(set(tags_nat)))

        # Tag os info, outweights os from http_useragent -- Check maybe no 'operating system' provided if os is set
        if t_family is not None:
            logger.debug(f"OS_family rewritten by info from tags: {os_family} -> {t_family}")
            os_family = t_family
        if t_type is not None:
            logger.debug(f"OS_type rewritten by info from tags: {os_type} -> {t_type}")
            os_type = t_type
        if t_version is not None:
            logger.debug(f"OS_version rewritten by info from tags: {os_version} -> {t_version}")
            os_version = t_version

        # Group
        if t_hw_type in ["computer", "mobile", "vehicle", "large-screen"]:
            group = "end_device"

        # Class
        if t_hw_type == "computer":
            _class = "workstation"
        if t_hw_type == "mobile" or t_hw_sub_type == "phone":
            _class = "mobile"

        # Taxonomy modifications
        # macOS
        if os_family in ["mac", "ios", "ios/100", "iphone", "ipad", "apple", "watchos"]:
            if os_family == "iphone":
                os_family = "macos"
                os_type = "ios"
            elif os_family == "ipad":
                os_family = "macos"
                os_type = "ipados"
            else:
                if os_type is None or os_type == "":
                    os_type = os_family
                os_family = "macos"

        # Unix
        if os_family == "darwin":
            os_family = "unix"
            os_type = "darwin"
        # Linux
        if os_family in [
            "chrome",
            "ubuntu",
            "rockz",
            "debian",
            "fedora",
            "redhat",
            "centos",
            "suse",
            "gentoo",
            "arch",
            "oracel",
            "linux/100",
        ]:
            if os_type == "rockz":
                os_type = "rocky"
            elif os_type == "oracel":
                os_type = "oracle"
            elif os_type == "chrome":
                os_type = "chromeos"
            else:
                os_type = os_family

            os_family = "linux"
        # windows
        if os_family in [
            "windows",
            "win",
            "windows/100",
        ]:
            if os_type is None or os_type == "":
                os_type = os_family
            os_family = "windows"

        if os_family not in ["macos", "windows", "linux", "android", "unix", None]:
            logger.debug(f"OS_family {os_family} not in taxonomy, manual fix needed")

        return [group, _class, os_family, os_type, os_version, multi_flag]

    @staticmethod
    def collect_useragents(ip_data, config: dict) -> list:
        """Function used to collect useragents from flows of one IP address.

        Parameters
        ----------
        ip_data : pd.DataFrame
            Flows of the IP address.
        config : dict
            Configuration of the useragent annotator.

        Returns
        -------
        list
            List of useragents for selected IP address.
        """

        if ip_data is None:
            return None

        http_useragents = ip_data[config["field"]].dropna().tolist()

        if len(http_useragents) > 0:
            return http_useragents

        return None

    @staticmethod
    def process_useragent(
        useragents,
        agent,
        src_ip,
        keywords,
        browsers_useragents,
        others_useragents,
        json,
        incomplete,
        mine_flag=True,
    ):
        """
        Processes and updates the useragents dictionary with recognized useragents.

        For each useragent, creates an instance of HTTP_useragent. If the placeholder created by this class
        exists in the dictionary, updates the device information; otherwise, runs find_in_table() to get tags
        and saves the new record to the dictionary.

        Parameters
        ----------
        useragents : dict
            Dictionary of translated useragents. Key is the placeholder variant of the useragent and value is an HTTP_useragent class instance.
        agent : str
            HTTP useragent string of the device from the biflow.
        src_ip : str
            IP address of the device from the biflow.
        keywords : dict
            Dictionary of keywords, where the key is a regex for the operating system.
        browsers_useragents : dict
            Dictionary of browser useragents, where the key is the placeholder variant of the useragent.
        others_useragents : dict
            Dictionary of other useragents, where the key is the placeholder variant of the useragent.
        json : str
            Name of the JSON file. If "", human-learning is disabled.
        incomplete : bool
            Indicates that the given useragent can be incomplete. Defaults to False.
        mine_flag : bool, optional
            Indicates if the mine_os label should be used if the record is not found in CSV tables. Defaults to True.
        """
        http_ua = translate.HTTP_useragent(
            agent,
            keywords,
            src_ip,
        )
        if http_ua.placeholder_useragent not in useragents:
            http_ua.find_in_table(
                browsers_useragents,
                others_useragents,
                json,
                keywords,
                incomplete,
                mine_flag,
            )
            useragents[http_ua.placeholder_useragent] = http_ua
        elif mine_flag:
            useragents[http_ua.placeholder_useragent].add_device(src_ip, http_ua.mine_os)
        else:
            useragents[http_ua.placeholder_useragent].add_device(src_ip, "")


class UserAgentDatabase:
    """Keyword and useragent tables used to translate useragents.

    Attributes
    ----------
    keywords : dict
        Keywords of operating systems.
    browsers : dict
        Table of browser useragents keyed by placeholder.
    others : dict
        Table of other useragents keyed by placeholder.
    """

    def __init__(self, keywords_db: str, browsers_db: str, others_db: str) -> None:
        """Load the databases.

        Parameters
        ----------
        keywords_db : str
            Path to the keywords database.
        browsers_db : str
            Path to the browsers useragents database.
        others_db : str
            Path to the other useragents database.
        """

        self.keywords = translate.load_keywords(keywords_db)
        self.browsers = translate.load_useragent_table(browsers_db)
        self.others = translate.load_useragent_table(others_db)


class UserAgentAnnotator(DAFModule):
    """Annotate IP addresses by the HTTP User-Agent strings in their flows.

    Attributes
    ----------
    database : UserAgentDatabase
        Keyword and useragent tables.
    """

    name = "useragent_annotator"
    description = "HTTP UserAgent Annotation"
    REQUIREMENTS = (
        Requirement("keywords_db", str, path="file"),
        Requirement("browsers_db", str, path="file"),
        Requirement("others_db", str, path="file"),
        Requirement("full_search", bool),
        Requirement("mine_flag", bool),
        Requirement("field", str),
    )
    DAF_REQUIREMENTS = (Requirement("min_annotation_count", int),)

    def setup(self) -> None:
        """Load the useragent databases."""

        self.database = UserAgentDatabase(
            self.config["keywords_db"], self.config["browsers_db"], self.config["others_db"]
        )

    def before_run(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Check that the useragent column is present in the flows.

        Parameters
        ----------
        ip_addresses : list
            IP objects that will be annotated.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.

        Raises
        ------
        ValueError
            If the useragent column is missing.
        """

        _, first_value = next(iter(flows_by_ip.items()))
        if self.config["field"] not in first_value.columns:
            logger.error("Column {} not found in the dataframe".format(self.config["field"]))
            raise ValueError("Column {} not found in the dataframe".format(self.config["field"]))

    def annotate_ip(self, ip, flows=None) -> None:
        """Translate the useragents of one IP address and annotate it.

        Parameters
        ----------
        ip : IP
            IP object to annotate.
        flows : pd.DataFrame, optional
            Flows of the IP.
        """

        http_useragents = UserAgentClassifier.collect_useragents(flows, self.config)
        processed_useragents = {}
        if http_useragents is None:
            return
        for agent in http_useragents:
            UserAgentClassifier.process_useragent(
                useragents=processed_useragents,
                agent=agent,
                src_ip=str(ip.ip_addr),
                keywords=self.database.keywords,
                browsers_useragents=self.database.browsers,
                others_useragents=self.database.others,
                json="",
                incomplete=self.config["full_search"],
                mine_flag=self.config["mine_flag"],
            )
        (
            group,
            _class,
            os_family,
            os_type,
            os_version,
            multi_flag,
        ) = UserAgentClassifier.annotation_from_useragents(
            processed_useragents,
            self.daf_config["min_annotation_count"],
        )
        ip.add_annotation(
            "useragent_annotator",
            Annotation(group, _class, os_family, os_type, os_version),
        )
        ip.add_data("useragent_annotator", http_useragents)

        if len(multi_flag) > 0:
            ip.multi_device.append(["UA", multi_flag])
