#!/usr/bin/python3
"""This module is for preparing .csv data (from whatismybrowser.com/useragents database) to two parts:
    1. Contains only useragents that starting with Mozilla. That mean every modern browsers or device that have useragnet looks like browser.
    2. Contains all other useragnet.

    Every part is reduced to "unique" only. Unique in this case means, 
    that module calculate placeholder variant for every useragent in table and leave in new table only one.
    (placeholder useragnet is created same way in translate_useragent.py module)
       --> this ways to quick calcualting for every useragent online 

    This module is intended for start-up before starting the measurement on the network, is for data pre-preparation. 

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
import time
from argparse import RawTextHelpFormatter
from pprint import pprint

# Local application imports
import create_placeholder
import numpy as np
import pandas as pd

CHUNKSIZE = 100000

NECESSARY_COLUMNS = [
    "user_agent",
    "simple_operating_platform_string",
    "software_name",
    "operating_system",
    "software_type",
    "software_sub_type",
    "hardware_type",
    "hardware_sub_type",
]
OUTPUT_COLUMNS = [
    "placeholder",
    "simple_operating_platform_string",
    "software_name",
    "operating_system",
    "software_type",
    "software_sub_type",
    "hardware_type",
    "hardware_sub_type",
]


def parse_arguments():
    """Function for set arguments of module.

    Returns:
        argparse: Return setted argument of module.
    """
    parser = argparse.ArgumentParser(
        description="""Prepare .csv file of known HTTP useragents and informations about them for working module translate_useragent.py.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="CSV file or path to csv file. (input with .csv)",
        type=str,
        metavar="FILE",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to dir where safe results of operations that split .csv file (from parameter -f) to two files. One contain browser useragents and second contain other useragents.",
        type=str,
        metavar="FOLDER",
        default="",
    )
    parser.add_argument(
        "-s",
        "--stat",
        help="Placeholder will have assigned tags that are most common in placeholder's useragents tags (assigned tag must occur in at least 60 percent of cases).",
        action="store_true",
    )
    parser.add_argument(
        "-a",
        "--add",
        help="CSV file or path to csv file, that will be added to .csv file from parameter -f. (input with .csv)",
        type=str,
        metavar="FILE",
        default="",
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
    if arg.add == "" and arg.output == "":
        print("Must be choosen one of parameters -o or -a.")
        sys.exit()
    if arg.file.endswith(".csv") is False:
        print("Entered file (-f) don't have suffix .csv")
        sys.exit()
    if os.path.exists(arg.file) is False:
        print("Entered file (-f) don't exists")
        sys.exit()
    if arg.add != "":
        if arg.add.endswith(".csv") is False:
            print("Entered file (-a) don't have suffix .csv")
            sys.exit()
        if os.path.exists(arg.add) is False:
            print("Entered file (-a) don't exists")
            sys.exit()
    return arg


def get_size(obj, seen=None):
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, "__dict__"):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size


def aggregate_file_with_statistics(arg, keywords):
    browser_useragents = {}
    other_useragents = {}
    cnt_chunk = 0
    len_necessary_columns = len(NECESSARY_COLUMNS)
    # load all rows from csv file for chunks
    for chunk in pd.read_csv(arg.file, chunksize=CHUNKSIZE):
        # for rows in chunks
        for i in range(0, len(chunk)):
            useragent = chunk.iloc[i]["user_agent"]
            # create placeholder/placeholder variant of useragent taht represent this row in new databases
            placeholder = create_placeholder.placeholder_useragent(useragent, keywords)
            if "Mozilla" in useragent:
                if placeholder not in browser_useragents:
                    browser_useragents[placeholder] = {}
                    for j in range(len_necessary_columns):
                        if NECESSARY_COLUMNS[j] == "user_agent":
                            continue
                        browser_useragents[placeholder][j] = {
                            chunk.iloc[i][NECESSARY_COLUMNS[j]]: 1
                        }
                else:
                    for j in range(len_necessary_columns):
                        if NECESSARY_COLUMNS[j] == "user_agent":
                            continue
                        if (
                            chunk.iloc[i][NECESSARY_COLUMNS[j]]
                            in browser_useragents[placeholder][j]
                        ):
                            browser_useragents[placeholder][j][
                                chunk.iloc[i][NECESSARY_COLUMNS[j]]
                            ] += 1
                        else:
                            browser_useragents[placeholder][j][
                                chunk.iloc[i][NECESSARY_COLUMNS[j]]
                            ] = 1

            else:
                if placeholder not in other_useragents:
                    other_useragents[placeholder] = {}
                    for j in range(len_necessary_columns):
                        if NECESSARY_COLUMNS[j] == "user_agent":
                            continue
                        other_useragents[placeholder][j] = {chunk.iloc[i][NECESSARY_COLUMNS[j]]: 1}
                else:
                    for j in range(len_necessary_columns):
                        if NECESSARY_COLUMNS[j] == "user_agent":
                            continue
                        if chunk.iloc[i][NECESSARY_COLUMNS[j]] in other_useragents[placeholder][j]:
                            other_useragents[placeholder][j][
                                chunk.iloc[i][NECESSARY_COLUMNS[j]]
                            ] += 1
                        else:
                            other_useragents[placeholder][j][
                                chunk.iloc[i][NECESSARY_COLUMNS[j]]
                            ] = 1
        cnt_chunk += 1
        print(
            f"Rows: {cnt_chunk}00k\n Rows others: {len(other_useragents)} Rows browsers: {len(browser_useragents)}"
        )
        # print(
        #     f"Memory ussage: {get_size(browser_useragents) + get_size(other_useragents)} bytes"
        # )
        print("--------------------------------------")

    now_time = time.time()  # run time
    browser_useragents = tags_by_statistics(browser_useragents)
    other_useragents = tags_by_statistics(other_useragents)
    end_time = time.time() - now_time  # stop time
    print(f"Time statistics: {end_time}")

    # print(
    #     f"Memory ussage: {get_size(browser_useragents) + get_size(other_useragents)} bytes"
    # )
    # at the end of passing rows from one chunk safe new placeholders rows to databases
    try:
        with open(arg.output + "browsers_useragents.csv", "a") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=OUTPUT_COLUMNS)
            for key in browser_useragents.keys():
                writer.writerow(browser_useragents[key])
    except IOError as e:
        print("I/O error")
    try:
        with open(arg.output + "others_useragents.csv", "a") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=OUTPUT_COLUMNS)
            for key in other_useragents.keys():
                writer.writerow(other_useragents[key])
    except IOError as e:
        print("I/O error")


def tags_by_statistics(useragents):
    useragents_tags = {}
    for placeholder in useragents.keys():
        useragents_tags[placeholder] = {
            "placeholder": placeholder,
        }
        for tag in useragents[placeholder]:
            finnal_tag = None
            sum_tag = 0
            for i in useragents[placeholder][tag].keys():
                sum_tag += useragents[placeholder][tag][i]
            for i in useragents[placeholder][tag].keys():
                if useragents[placeholder][tag][i] * 100 / sum_tag >= 60:
                    if str(i) != "nan" and str(i) != "":
                        finnal_tag = f"{i}/{int(useragents[placeholder][tag][i] * 100 / sum_tag)}"
                    break
            if finnal_tag is not None:
                useragents_tags[placeholder][NECESSARY_COLUMNS[tag]] = finnal_tag
            else:
                useragents_tags[placeholder][NECESSARY_COLUMNS[tag]] = ""
    return useragents_tags


def aggregate_file(arg, keywords):
    """Fucntion pass all rows in given database, spit them to two database.
    Also reduce them gz using placeholder algorithm.

    Args:
        arg (agsparse): Arguments of module.
        keywords (dict): Database of keywords OS for mine_os module.
    """
    browser_useragents = {}
    browser_keys = []
    other_useragents = {}
    other_keys = []
    cnt_chunk = 0
    # load all rows from csv file for chunks
    for chunk in pd.read_csv(arg.file, chunksize=CHUNKSIZE):
        # for rows in chunks
        for i in range(0, len(chunk)):
            useragent = chunk.iloc[i]["user_agent"]
            # create placeholder/placeholder variant of useragent taht represent this row in new databases
            placeholder = create_placeholder.placeholder_useragent(useragent, keywords)
            if re.match(".*Mozilla.*", useragent):
                # if start with Mozilla, then it is browser's useragent
                if placeholder not in browser_useragents:
                    # get to new database only unique placeholder
                    browser_useragents[placeholder] = {}
                    browser_keys.append(placeholder)
                    browser_useragents[placeholder]["placeholder"] = placeholder
                    for col in NECESSARY_COLUMNS:
                        if col == "user_agent":
                            continue
                        browser_useragents[placeholder][col] = chunk.iloc[i][col]

            else:
                # else, then is other application's useragent
                if placeholder not in other_useragents:
                    # get to new database only unique placeholder
                    other_useragents[placeholder] = {}
                    other_keys.append(placeholder)
                    other_useragents[placeholder]["placeholder"] = placeholder
                    for col in NECESSARY_COLUMNS:
                        if col == "user_agent":
                            continue
                        other_useragents[placeholder][col] = chunk.iloc[i][col]
        # at the end of passing rows from one chunk safe new placeholders rows to databases
        cnt_chunk += 1
        print(
            f"Rows: {cnt_chunk}00k\n Rows others: {len(other_useragents)} Rows browsers: {len(browser_useragents)}"
        )
        print("--------------------------------------")
        if os.path.exists(arg.output + "browsers_useragents.csv") is False:
            try:
                with open(arg.output + "browsers_useragents.csv", "w") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=OUTPUT_COLUMNS)
                    writer.writeheader()
                    for data in browser_keys:
                        writer.writerow(browser_useragents[data])
                    for k in browser_keys:
                        browser_useragents[k] = None
                    browser_keys.clear()
            except IOError as e:
                print("I/O error")
            try:
                with open(arg.output + "others_useragents.csv", "w") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=OUTPUT_COLUMNS)
                    writer.writeheader()
                    for data in other_keys:
                        writer.writerow(other_useragents[data])
                    for k in other_keys:
                        other_useragents[k] = None
                    other_keys.clear()
            except IOError as e:
                print("I/O error")
        else:
            try:
                with open(arg.output + "browsers_useragents.csv", "a") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=OUTPUT_COLUMNS)
                    for data in browser_keys:
                        writer.writerow(browser_useragents[data])
                    for k in browser_keys:
                        browser_useragents[k] = None
                    browser_keys.clear()
            except IOError as e:
                print("I/O error")
            try:
                with open(arg.output + "others_useragents.csv", "a") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=OUTPUT_COLUMNS)
                    for data in other_keys:
                        writer.writerow(other_useragents[data])
                    for k in other_keys:
                        other_useragents[k] = None
                    other_keys.clear()
            except IOError as e:
                print("I/O error")


def append_row(file, row, l, headers, added_useragents, keywords):
    # check if useragent row exists in
    useragent = create_placeholder.placeholder_useragent(row[headers[int(l[0])]], keywords)
    if useragent in added_useragents:
        return
    for chunk in pd.read_csv(file, chunksize=CHUNKSIZE):
        if useragent in chunk["user_agent"].values:
            return  # recod was found, not need to add second one
    # create new row for adding to file
    new_row = {}
    for i in range(0, len(NECESSARY_COLUMNS)):
        if l[i] == "-":
            new_row[NECESSARY_COLUMNS[i]] = ""
        else:
            new_row[NECESSARY_COLUMNS[i]] = row[headers[int(l[i])]]
    new_row["user_agent"] = useragent
    print(new_row["user_agent"])
    added_useragents[new_row["user_agent"]] = ""
    # writing the data into the file
    with open(file, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=NECESSARY_COLUMNS)
        writer.writerow(new_row)


def add_data_to_file(arg, keywords):
    # get type data in file (browsers or others useragents)
    t = False
    for chunk in pd.read_csv(arg.file, chunksize=1):
        useragent = chunk.iloc[0]["user_agent"]
        if re.match(".*Mozilla.*", useragent):
            t = True
        break
    # adding rows
    added_useragents = {}
    with open(arg.add, "r") as f:
        d_reader = csv.DictReader(f)
        # get fieldnames from DictReader object and store in list
        headers = d_reader.fieldnames
        tmp = 0
        print(
            "Choose column name in adding file that will be putted to existing file column (choosing by number). You can fill - place to number, if you want column be blank."
        )
        for i in headers:
            print(f"{tmp} ... {i}")
            tmp += 1
        print("-----------------------------------")
        l = []
        for i in NECESSARY_COLUMNS:
            print(f"{i}:", end="")
            num = input()
            l.append(num)
        for row in d_reader:
            if re.match(".*Mozilla.*", row[headers[int(l[0])]]):
                if t is True:
                    append_row(arg.file, row, l, headers, added_useragents, keywords)
            elif t is False:
                append_row(arg.file, row, l, headers, added_useragents, keywords)


def load_keywords(filename):
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
    if arg.add != "":
        add_data_to_file(arg, keywords)
    elif arg.output != "":
        if arg.stat is False:
            aggregate_file(arg, keywords)
        else:
            aggregate_file_with_statistics(arg, keywords)
    else:
        pass


if __name__ == "__main__":
    main()
