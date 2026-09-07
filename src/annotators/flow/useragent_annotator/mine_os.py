#!/usr/bin/python3
"""
Mine OS module is used to mine operating system from HTTP useragent string. 
Module can be runned alone or can be called from another module for get OS information.

From mining are used three python dictionaries, that are writen in this module, and csv file, that contains os keywords. 

Copyright (C) 2021 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above.

This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.

"""
import argparse
import csv
import os
import re

# Standard libraries imports
import sys
from argparse import RawTextHelpFormatter

import pandas as pd

WINDOWS_REGEX = {
    "Windows.NT.5.0": "Windows 2000",
    "Windows.NT.5.1": "Windows XP",
    "Windows.NT.5.2": "Windows Server 2003",
    "Windows.NT.6.0": "Windows Vista",
    "Windows.NT.6.1": "Windows 7",
    "Windows.NT.6.2": "Windows 8",
    "Windows.NT.6.3": "Windows 8.1",
    "Windows.NT.10.0": "Windows 10",
    "Windows.NT": "Windows NT",
    "Windows.ME": "Windows ME",
    "Windows.CE": "Windows CE",
    "Windows.Phone \d.\d": "Windows Phone",
    "Windows.98": "Windows 98",
    "Windows.95": "Windows 95",
}

MAC_REGEXS = {
    "Intel.Mac.OS.X.10_12": "Mac OS X 10.12 (Sierra)",
    "Intel.Mac.OS.X.10_11": "Mac OS X 10.11 (El Capitan)",
    "Intel.Mac.OS.X.10_10": "Mac OS X 10.10 (Yosemite)",
    "Intel.Mac.OS.X.10_90": "Mac OS 10.90",
    "Intel.Mac.OS.X.10_9": "Mac OS X 10.9 (Mavericks)",
    "Intel.Mac.OS.X.10_8": "Mac OS X 10.8 (Mountain Lion)",
    "Intel.Mac.OS.X.10_7": "Mac OS X 10.7 (Lion)",
    "Intel.Mac.OS.X.10_6": "Mac OS X 10.6 (Snow Leopard)",
    "Intel.Mac.OS.X.10_5": "Mac OS X 10.5 (Leopard)",
    "Intel.Mac.OS.X.10_4": "Mac OS X 10.4 (Tiger)",
    "Intel.Mac.OS.X.10.12": "Mac OS X 10.12 (Sierra)",
    "Intel.Mac.OS.X.10.11": "Mac OS X 10.11 (El Capitan)",
    "Intel.Mac.OS.X.10.10": "Mac OS X 10.10 (Yosemite)",
    "Intel.Mac.OS.X.10.9": "Mac OS X 10.9 (Mavericks)",
    "Intel.Mac.OS.X.10.8": "Mac OS X 10.8 (Mountain Lion)",
    "Intel.Mac.OS.X.10.7": "Mac OS X 10.7 (Lion)",
    "Intel.Mac.OS.X.10.6": "Mac OS X 10.6 (Snow Leopard)",
    "Intel.Mac.OS.X.10.5": "Mac OS X 10.5 (Leopard)",
    "Intel.Mac.OS.X.10.4": "Mac OS X 10.4 (Tiger)",
    "Intel.Mac.OS.X": "Mac OS X",
}

ANDROID_REGEX = {
    "Android.2(.[01])*": "Android 2 (Eclair)",
    "Android.2(.2)*": "Android 2.2 (Froyo)",
    "Android.2(.3)*": "Android 2.3 (Gingerbread)",
    "Android.3(.[012])*": "Android 3 (Honeycomb)",
    "Android.4(.0)*": "Android 4.0 (Ice Cream Sandwich)",
    "Android.4(.[123])*": "Android 4.3 (Jelly Bean)",
    "Android.4(.4)*": "Android 4.4 (KitKat)",
    "Android.5(.[01])*": "Android 5 (Lollipop)",
    "Android.6(.0)*": "Android 6.0 (Marshmallow)",
    "Android.7(.[01])*": "Android 7 (Nougat)",
    "Android.8(.[01])*": "Android 8 (Oreo)",
    "Android.9(.0)*": "Android 9.0 (Pie)",
    "Android.10(.0)*": "Android 10.0",
    "Android.11(.0)*": "Android 11.0",
}


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
    parser.add_argument(
        "-k",
        "--keywords",
        help="Database of keywords with operating system to find in useragent. Keyword in dcsv file is regex for re library.",
        type=str,
        metavar="<file.suffix>",
        default="Keywords.csv",
    )
    arg = parser.parse_args()
    return arg


def find_keywords(useragent, keywords):
    """Go through all the keywords and try to math some of them in useragent.

    Args:
        useragent (str): HTTP useragent string.

    Returns:
        str: OS name string or None when doesn't found enything.
    """
    for regex in keywords.keys():
        if re.search(rf"{regex}", useragent):
            return keywords[regex]
    return None


def find_os(useragent, regexes):
    """Try to find match in patern dictionary regexes (WINDOWS_REGEX or MAC_REGEXS or ANDROID_REGEX).

    Args:
        useragent (str): String of HTTP useragent.
        regexes (dict): Given dictionary of pattern for specific os type (Widnows or MAC or Android).

    Returns:
        str: Return OS or None.
    """
    for pattern in regexes.keys():
        if re.search(pattern, useragent):
            return regexes[pattern]
    return None


def mine_os(useragent, keywords):
    """Mine OS from given useragent string, by using re library and regex patterns
    from dictionaries and csv file in dcitionary keywords.

    Args:
        useragent (str): String of HTTP useragent.
        keywords (dict): CSV file of keywords loaded in dictionary.

    Returns:
        str: String OS or None.
    """
    # Windows
    if re.search("[wW]indows", useragent):
        win = find_os(useragent, WINDOWS_REGEX)
        if win is not None:
            return win
        return "Windows"
    # Mac OS
    if re.search("Intel Mac OS X", useragent):
        mac = find_os(useragent, MAC_REGEXS)
        if mac is not None:
            return mac
        return "Mac OS"
    # Amazon Kindle
    if (
        re.search("Silk", useragent)
        or re.search("Kindle", useragent)
        or re.search("KFTHWI Build", useragent)
    ):
        return "Fire OS (Kindle)"
    # Android
    if re.search("[aA]ndroid", useragent):
        android = find_os(useragent, ANDROID_REGEX)
        if android is not None:
            return android
        return "Android"
    # iPhone iOS
    search = re.search("CPU iPhone OS (?P<version>[\d_]*) like Mac OS X", useragent)
    if search:
        return "iPhone iOS {version}".format(**search.groupdict()).replace("_", ".")
    search = re.search("CPU OS (?P<version>[\d_]*) like Mac OS X", useragent)
    if search:
        return "iPhone iOS {version}".format(**search.groupdict()).replace("_", ".")
    search = re.search("iOS (?P<version>[\d_\.]*)", useragent)
    if search:
        return "Apple iOS {version}".format(**search.groupdict()).replace("_", ".")
    # Debian
    search = re.search("Debian GNU/Linux (?P<version>[\d_\.]*)", useragent)
    if search:
        return "Depian {version}".format(**search.groupdict())
    # Chrome OS
    search = re.search("CrOS (?P<procesor>[\w\d_\.]*) (?P<version>[\d_\.]*)", useragent)
    if search:
        return "Chrome OS {version}".format(**search.groupdict())
    # Keywords
    keyword = find_keywords(useragent, keywords)
    if keyword is not None:
        return keyword
    return None


def testing_translate_csv_file(csv_file, ip_field, ua_field, keywords):
    """Function for mine os in given csv file. Print results to command line.

    Args:
        csv_file (str): Name of csv file.
        field (str): Column in csvfile where is stored HTTP useragent.
        keywords (dict): CSV file of keywords loaded in dictionary.
    """
    f_useragents = {}
    reader = pd.read_csv(csv_file, chunksize=1000)
    for chunk in reader:
        for i in range(0, len(chunk)):
            usr = str(chunk.iloc[i][ua_field])
            if usr != "nan":
                if usr in f_useragents:
                    continue
                f_useragents[usr] = mine_os(usr, keywords)
                # if f_useragents[row[5]] != None:
                print(f"{str(chunk.iloc[i][ip_field])}, {usr}: \t{f_useragents[usr]}")


def load_keywords(filename):
    """Load keywords from csv file and store them to dictionary.

    Args:
        filename (str): name of csv file that contains keywords.

    Returns:
        dict: Dictionary of keywords.
    """
    if filename.endswith(".csv") is False:
        print("The filename of table contains filter haven't suffix or isn't .csv")
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


def main():
    """Main function of the module."""
    arg = parse_arguments()
    keywords = load_keywords(arg.keywords)
    # testing_regex_func()
    if arg.csv is not None:
        testing_translate_csv_file(arg.csv, arg.ipfield, arg.useragentfield, keywords)
    else:
        print("Input HTTP useragent:")
        http_useragent = input()
        print("##################################################################################")
        print(mine_os(http_useragent, keywords))


if __name__ == "__main__":
    main()
