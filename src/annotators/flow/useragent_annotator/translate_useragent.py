#!/usr/bin/python3
"""
Author(s): Josef Koumar <koumar@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: translate_useragent.py
Description:
Transleate useragent module contains HTTP_useragent class, that provides founding tags about useragent in csv tables, by
keywords of operating systems and keywords of device type. All tags are safed in class variables.

Module is determined for calling from another module, but can be runned from cmd as separate module, that translate single
useragent or csv table of useragents, and print tags to output.
"""

import argparse
import csv
import json
import os
import re

# Standard libraries imports
import sys
import time
from argparse import RawTextHelpFormatter

import pandas as pd

# Local module imports
from . import create_placeholder as create_placeholder
from . import mine_os as mo

# Constants
# columns in given csv tables, that are necessary
NECESSARY_COLUMNS = [
    "simple_operating_platform_string",
    "software_name",
    "operating_system",
    "software_type",
    "software_sub_type",
    "hardware_type",
    "hardware_sub_type",
]

# template for human-learning JSON
JSON_TEMPLATE = {
    "useragent": None,
    "src_ip": None,
    "mine_os": None,
    "mine_device": None,
}


class HTTP_useragent:
    """HTTP_useragent class working with given useragent to provide translate to tags, safe tags,
    or in some cases safe useragent to JSON for human-learning.
    """

    def __init__(self, useragent, keywords, src_ip=None):
        """Init fucntion of class, that safe all given variables and translate useragent to placeholder variant.

        Args:
            useragent (str): HTTP useragent.
            keywords (dict): Dict of keywords of operating system, required for transalte useragent to placeholder variant.
            src_ip (str): IP address of device with this useragent. Defaults to None.
        """
        self.useragent = [
            useragent,
        ]
        self.src_ip = []
        self.os = []
        self.tags = {}
        self.mine_os = mo.mine_os(self.useragent[0], keywords)
        self.device = self.mine_device(self.useragent[0])
        if src_ip is not None:
            self.src_ip.append(src_ip)
        self.placeholder_useragent = create_placeholder.placeholder_useragent(useragent, keywords)

    def __eq__(self, other):
        if self.placeholder_useragent == other.placeholder_useragent:
            return True
        return False

    def __str__(self):
        tmp = f"{self.src_ip},{self.useragent}"
        for i in self.tags.keys():
            tmp += f",{i}:{self.tags[i]}"
        return tmp

    def copy_useragent(self, other):
        for i in other.tags.keys():
            self.tags[i] = other.tags[i]

    # instance methods
    def find_in_table(
        self, browsers, others, json_file, keywords, incomplete=False, mine_flag=True
    ):
        """Main fucntion of class. By call this function with csv tables (browsers, others and keywords) as dict transalte this
        useragent to tags. Tags are safed into instance class variable tags.

        Function have two ways for transalte useragent to tags. First required complete useragent (and it is speed).
        Second can translate incomplete useragents (but it is slow). Variant is choosing by variable incomplete.
        Default value of incomplte variable is False, that mean first variant is enable.

        Args:
            browsers (dict): CSV table contains browsers useragents in dict where key is placeholder variant of useragent.
            others (dict): CSV table contains other useragents in dict where key is placeholder variant of useragent.
            json_file (str): Name of json file. If is "" then human-learning is disable.
            keywords (dict): CSV table contains keywords in dict where key is regex of operating system.
            incomplete (bool): Variables says that given useragent can be incomplete. Defaults to False.
            mine_flag (bool): Variable says if mine_os label should be used, if record not found in CSV tables. Defaults to True.
        """
        part = None
        # choose in which csv table is that types of useragents
        if self.useragent[0].startswith("Mozilla") is True:
            table = browsers
        else:
            if re.search(".*Mozilla.*", self.useragent[0]):
                table = browsers
            else:
                table = others

        if incomplete is True:
            # 2. Method string comparing with incomplete string 0.13s for last item
            for i in table:
                if i.startswith(self.placeholder_useragent) is True:
                    part = table[i]
                    break
            if mine_flag and (part is None or part == []):
                if self.mine_os != "":
                    self.os.append(self.mine_os)
                if json_file == "":
                    return
                self.human_learning(json_file)
                return
        else:
            # 1. Method string comparing ~0.0002s for last item
            try:
                part = table[self.placeholder_useragent]
            except KeyError:
                if mine_flag and self.mine_os != "":
                    self.os.append(self.mine_os)
                if json_file == "":
                    return
                self.human_learning(json_file)
                return
        # safe founded tags
        if part is not None and part != []:
            self.safe_founded_tags(part)

    def safe_founded_tags(self, part, mine_flag=True):
        """Tags from part variable have keys from NECESSARY_COLUMN constant.
        This function take parts and every tag which have come value, safe.

        If tag and tag_sub have values, then in tag key is safe tag_sub, becouse it is more specific.

        Args:
            part (dict): Dictionary of NECESSARY_COLUMN, where tags are safed.
            mine_flag (bool): Variable says if mine_os label should be used, if record not found in CSV tables. Defaults to True.
        """
        # Operating system
        if part["operating_system"] != "nan" and part["operating_system"] != "":
            if self.mine_os is not None:
                if re.search("\*", self.mine_os):
                    self.os.append(f"{part['operating_system']}/{self.mine_os}")
                elif mine_flag:
                    self.os.append(self.mine_os)
            else:
                self.os.append(part["operating_system"])
        else:
            if mine_flag and self.mine_os is not None:
                self.os.append(self.mine_os)
            else:
                self.os.append("")
        # Hardware type == Device type
        if self.device is not None and (
            part["hardware_type"] == "nan" or part["hardware_type"] == ""
        ):
            self.tags["hardware_type"] = self.device
        elif part["hardware_type"] != "nan" and part["hardware_type"] != "":
            if part["hardware_sub_type"] != "nan" and part["hardware_sub_type"] != "":
                self.tags["hardware_type"] = part["hardware_sub_type"]
            else:
                self.tags["hardware_type"] = part["hardware_type"]
        # Operating platform
        if (
            part["simple_operating_platform_string"] != "nan"
            and part["simple_operating_platform_string"] != ""
        ):
            self.tags["simple_operating_platform_string"] = part["simple_operating_platform_string"]
        # Software name
        if part["software_name"] != "nan" and part["software_name"] != "":
            self.tags["software_name"] = part["software_name"]
        # Software type
        if part["software_type"] != "nan" and part["software_type"] != "":
            if part["software_sub_type"] != "nan" and part["software_sub_type"] != "":
                self.tags["software_type"] = part["software_sub_type"]
            else:
                self.tags["software_type"] = part["software_type"]

    def mine_device(self, useragent):
        """Mine device from useragent by using some keywords of device dype.

        Args:
            useragent (str): HTTP useragent.

        Returns:
            str: Return device type, or None if doesn't keywords math.
        """
        if re.search("[tT]ablet", useragent):
            return "tablet"
        if re.search("[mM]obile", useragent):
            return "mobile"
        if re.search("i[pP]hone", useragent):
            return "iPhone"
        if re.search("i[pP]ad", useragent):
            return "iPad"
        return None

    def get_tags(self):
        """Return tags and all posible variables, as IP, Domain, useragent.

        Returns:
            dict: Dictionary with all variables and tags.
        """
        if self.tags == {}:
            return (
                self.placeholder_useragent,
                {
                    "src_ip": self.src_ip,
                    "user_agent": self.useragent[0],
                    "tags": "",
                },
            )
        return (
            self.placeholder_useragent,
            {
                "src_ip": self.src_ip,
                "user_agent": self.useragent[0],
                "tags": self.tags,
            },
        )

    def create_json(self, json_file, data):
        """Creagte json file for human-learning and safe to him first record.

        Args:
            json_file (str): Name of json, taht willl be created.
            data (dict): Data taht will be safe in created json as first record.
        """
        json_data = {self.placeholder_useragent: data}
        with open(json_file, "w") as outfile:
            json.dump(json_data, outfile)

    def human_learning(self, json_file):
        """Process data to human learning JSON file.

        Args:
            json_file (str): Name of json, taht willl be created.
        """
        # create record for JSON
        data = JSON_TEMPLATE
        data["useragent"] = self.useragent[0]
        data["src_ip"] = self.src_ip[0]
        data["mine_os"] = self.mine_os
        data["mine_device"] = self.device
        if os.path.exists(json_file) is False:
            # if file don't exists, create new one
            self.create_json(json_file, data)
        else:
            # else file exists, push record to end
            with open(json_file, "r+") as f:
                d = json.load(f)
                if self.placeholder_useragent not in d.keys():
                    d.update({self.placeholder_useragent: data})
                    f.seek(0)
                    json.dump(d, f)

    def add_device(self, src_ip, os, agent=None):
        if src_ip not in self.src_ip:
            self.src_ip.append(src_ip)
            if os is not None:
                self.os.append(os)
            else:
                self.os.append("")
            if agent is not None:
                self.useragent.append(agent)


def parse_arguments():
    """Function for set arguments of module.

    Returns:
        argparse: Return setted argument of module.
    """
    parser = argparse.ArgumentParser(
        description="""Find information about device from HTTP useragent.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "-b",
        "--browsers",
        help="CSV file or path to csv file that contains browsers useragents. (input with .csv)",
        type=str,
        metavar="<file.suffix>",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--others",
        help="CSV file or path to csv file that contains other useragents. (input with .csv)",
        type=str,
        metavar="<file.suffix>",
        required=True,
    )
    parser.add_argument(
        "-j",
        "--json",
        help="JSON file for human learning.",
        type=str,
        metavar="<file.suffix>",
        default="",
        # required=True,
    )
    parser.add_argument(
        "-k",
        "--keywords",
        help="Database of keywords with operating system to find in useragent. Keyword in dcsv file is regex for re library.",
        type=str,
        metavar="<file.suffix>",
        default="Keywords.csv",
    )
    parser.add_argument("-I", help="Choose method for incomplete useragents.", action="store_true")
    parser.add_argument(
        "-c",
        "--csv",
        help="Testing csv file contains useragents with other information from probes.",
        type=str,
        metavar="<file.suffix>",
        default=None,
    )
    parser.add_argument(
        "-u",
        "--useragentfield",
        help="Name of useragent field in csv table from --csv parameter.",
        type=str,
        metavar="<file.suffix>",
        default="string HTTP_REQUEST_USER_AGENT",
    )
    parser.add_argument(
        "-i",
        "--ipfield",
        help="Name of ip address field in csv table from --csv parameter.",
        type=str,
        metavar="<file.suffix>",
        default="ipaddr SRC_IP",
    )
    arg = parser.parse_args()
    if arg.browsers.endswith(".csv") is False:
        print("Entered browsers file (-b) don't have suffix .csv")
        sys.exit()
    if os.path.exists(arg.browsers) is False:
        print("Entered browsers file (-b) don't exists")
        sys.exit()
    if arg.others.endswith(".csv") is False:
        print("Entered others file (-o) don't have suffix .csv")
        sys.exit()
    if os.path.exists(arg.others) is False:
        print("Entered others file (-o) don't exists")
        sys.exit()
    return arg


def testing_translate_csv_file(
    browsers_file,
    others_file,
    json_file,
    csv_file,
    incomplete,
    keywords,
    useragentfield,
    ipfield,
):
    """Function is for transalte csv file of useragents and print output to standard output.

    Args:
        browsers_file (dict): CSV table contains browsers useragents in dict where key is placeholder variant of useragent.
        others_file (dict): CSV table contains other useragents in dict where key is placeholder variant of useragent.
        json_file (str): Name of json file. If is "" then human-learning is disable.
        csv_file (str): CSV table contains useragents.
        incomplete (bool): Variables says that given useragent can be incomplete. Defaults to False.
        keywords (dict): CSV table contains keywords in dict where key is regex of operating system.
        useragentfield (str): Name of column, where useragent is safed.
        ipfield (str): Name of column, where ip address is safed.
    """
    f_useragents = {}
    reader = pd.read_csv(csv_file, chunksize=1000)
    for chunk in reader:
        for i in range(0, len(chunk)):
            usr = str(chunk.iloc[i][useragentfield])
            if usr != "nan":
                if usr in f_useragents:
                    continue
                http_useragent = HTTP_useragent(usr, keywords)
                f_useragents[usr] = None
                http_useragent.find_in_table(
                    browsers_file, others_file, json_file, keywords, incomplete
                )
                for j in http_useragent.tags.keys():
                    if (
                        http_useragent.tags[j] != ""
                        and str(http_useragent.tags[j]) != "nan"
                        and j == "operating_system"
                    ):
                        if http_useragent.mine_os == None:
                            print(
                                f"{str(chunk.iloc[i][ipfield])}, {usr}: \t{http_useragent.tags[j]}"
                            )
                        if re.search("/", str(http_useragent.tags[j])):
                            print(
                                f"{str(chunk.iloc[i][ipfield])}, {usr}: \t{http_useragent.tags[j]}"
                            )


def load_keywords(filename):
    """Load keywords from csv table to dict

    Args:
        filename (str): nme os CSV file where keywords are safed.

    Returns:
        dict: CSV table contains keywords in dict where key is regex of operating system.
    """
    if filename.endswith(".csv") is False:
        print("The filename of table contains keywords haven't suffix or isn't .csv")
        sys.exit(1)
    if os.path.isfile(filename) is False:
        print(f"The file with name {filename} doesn't exists.")
        sys.exit(1)
    try:
        with open(filename, mode="r", encoding="utf-8") as infile:
            reader = csv.reader(infile)
            filter = dict((str(rows[0]), str(rows[1])) for rows in reader)
        return filter
    except Exception as e:
        print(f"Error in loading file {filename}: {e}")
        sys.exit(1)


def load_useragent_table(filename):
    """Load data for browsers or others sueragent to dict.

    Args:
        filename (str): Name of CSV file, where browsers useragent or others useragents are safed.

    Returns:
        [dict: CSV table contains browsers useragents in dict where key is placeholder variant of useragent.
    """
    if filename.endswith(".csv") is False:
        print("The filename of table contains useragent table haven't suffix or isn't .csv")
        sys.exit(1)
    if os.path.isfile(filename) is False:
        print(f"The file with name {filename} doesn't exists.")
        sys.exit(1)
    try:
        with open(filename, mode="r", encoding="utf-8") as infile:
            reader = csv.reader(infile)
            useragent_table = dict()
            for rows in reader:
                useragent_table[str(rows[0])] = {
                    "simple_operating_platform_string": str(rows[1]),
                    "software_name": str(rows[2]),
                    "operating_system": str(rows[3]),
                    "software_type": str(rows[4]),
                    "software_sub_type": str(rows[5]),
                    "hardware_type": str(rows[6]),
                    "hardware_sub_type": str(rows[7]),
                }
        return useragent_table
    except Exception as e:
        print(f"Error in loading file {filename}: {e}")
        sys.exit(1)


def main():
    """Main function of the module."""
    arg = parse_arguments()
    keywords = load_keywords(arg.keywords)
    browsers = load_useragent_table(arg.browsers)
    others = load_useragent_table(arg.others)
    if arg.csv is not None:
        testing_translate_csv_file(
            browsers,
            others,
            arg.json,
            arg.csv,
            arg.I,
            keywords,
            arg.useragentfield,
            arg.ipfield,
        )
    else:
        print("Input HTTP useragent:")
        http_useragent = input()
        print("##################################################################################")
        hua = HTTP_useragent(http_useragent, keywords)
        hua.find_in_table(browsers, others, arg.json, keywords, arg.I)
        print(hua.placeholder_useragent)
        # print(hua.get_tags())
        print("Tags:")
        if hua.os is not None and hua.os != "":
            print(f"Operating system: {hua.os[0]}")
        for i in hua.tags.keys():
            if hua.tags[i] != "" and str(hua.tags[i]) != "nan":
                print(f" {i}: {hua.tags[i]}")


if __name__ == "__main__":
    main()
