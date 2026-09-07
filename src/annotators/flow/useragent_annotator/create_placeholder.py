#!/usr/bin/python3
"""
Author(s): Josef Koumar <koumar@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: create_placeholder.py
Description:
The module contains functions that convert the useragent to a version-less, processor-less,
system-less variant of the useragent in order to make a faster search in the csv table and its
rapid reduction in data preparation.
"""

# Python libraries
import re

# Local Aplication Imports
from .mine_os import mine_os


def placeholder_useragent(useragent, keywords):
    """Main function of this module. This fucntion is called from another modules to get placeholder useragent.

    Args:
        useragent (str): String of HTTP useragent.
        keywords (dict): Keywords of OSs for mine_os module.

    Returns:
        str: Placeholder version of useragent
    """
    placeholder = ""
    # first proces ()
    start_bracket = useragent.split("(")
    for i in range(0, len(start_bracket)):
        end_bracket = start_bracket[i].split(")")
        len_br = len(end_bracket)
        if len_br == 2:  # for: ...(...)...
            if end_bracket[1] != "":  # in useragent
                bracket = get_placeholder_bracket(end_bracket[0], keywords)
                placeholder += f"({bracket}) "
                # rest are product X/ver ...
                if re.search("\[", end_bracket[1]):
                    # Mozilla/1215 (X; Y; Z/123; rv:1) P1/123 [X; Y/123; Z] P2/123  ->  Mozilla# (X;Y;Z#;rv:#) P1# [X;Y#;Z] P2#
                    placeholder += get_another_bracket(end_bracket[1], keywords, "[", "]")
                else:
                    tmp = " " + end_bracket[1] + " "
                    if (
                        re.search(" AS ", tmp)
                        or re.search(" ORDER ", tmp)
                        or re.search(" SELECT ", tmp)
                    ):
                        placeholder += "#"
                        break
                    placeholder += get_placeholder_products(end_bracket[1])
            else:  # on end of useragent
                bracket = get_placeholder_bracket(end_bracket[0], keywords)
                placeholder += f"({bracket}) "
        elif len_br == 1:
            if i != 0 and len(start_bracket) != 1:
                placeholder += f"({get_placeholder_bracket(end_bracket[0], keywords)}"
            else:
                # product X/ver ...
                if re.search("\[", start_bracket[i]):
                    # Mozilla/1215 (X; Y; Z/123; rv:1) P1/123 [X; Y/123; Z] P2/123  ->  Mozilla# (X;Y;Z#;rv:#) P1# [X;Y#;Z] P2#
                    placeholder += get_another_bracket(start_bracket[i], keywords, "[", "]")
                elif re.search("/", start_bracket[i]):
                    placeholder += get_placeholder_products(start_bracket[i])
                else:
                    tmp = " " + end_bracket[i] + " "
                    if re.search(" ORDER ", tmp) or re.search(" SELECT ", tmp):
                        placeholder += "#"
                        break
                    placeholder += get_placeholder_products(start_bracket[i])
        else:  # for ...(...(...)...)...
            placeholder += "("  # for: Product/ver ( ... )...)
            for i in range(0, len_br - 1):
                bracket = get_placeholder_bracket(end_bracket[i], keywords)
                placeholder += f"{bracket}) "
            # rest are product X/ver ...
            if re.search("\[", end_bracket[-1]):
                # Mozilla/1215 (X; Y; Z/123; rv:1) P1/123 [X; Y/123; Z] P2/123  ->  Mozilla# (X;Y;Z#;rv:#) P1# [X;Y#;Z] P2#
                placeholder += get_another_bracket(end_bracket[-1], keywords, "[", "]")
            else:
                tmp = " " + end_bracket[-1] + " "
                if (
                    re.search(" AS ", tmp)
                    or re.search(" ORDER ", tmp)
                    or re.search(" SELECT ", tmp)
                ):
                    placeholder += "#"
                    break
                placeholder += get_placeholder_products(end_bracket[-1])
    return placeholder


def get_placeholder_bracket(bracket, keywords):
    """Get placeholder of inner space in brackets.

    Args:
        bracket  (str): String inner of bracket in HTTP useragent.
        keywords (dict): Keywords of OSs for mine_os module.

    Returns:
        str: placeholder variant of bracket
    """
    placeholder = ""
    # check if in bracket isinformation about OS
    os = mine_os(bracket, keywords)
    # split by semicolon (in brackets are always semicolon)
    if re.search("; ", bracket):
        semicolon = bracket.split("; ")
    else:
        semicolon = bracket.split(";")
    if os is not None:
        # if mine_os finds os, make data more anonymous becouse we dont need them (always)
        # example: Mozilla/1215 (Windows NT 5.1; X; Y/123; rv:alfsdkjasdf) -> Mozilla# (#; #; Y/#; #)
        if len(semicolon) == 1:
            return create_bracket_product(semicolon[0], False, "#", "")
        for i in range(0, len(semicolon) - 1):
            placeholder += create_bracket_product(semicolon[i], False, "#", ";")
        placeholder += create_bracket_product(semicolon[len(semicolon) - 1], False, "#", "")
    else:
        # in bracket isn't os informatin, make data less anonymous, we probably need these data
        # example: Mozilla/1215 (X; Y; Z/123; rv:alfsdkjasdf) -> Mozilla# (X; Y; Y/#; rv:#)
        if len(semicolon) == 1:
            return create_bracket_product(semicolon[0], True, "#", "")
        for i in range(0, len(semicolon) - 1):
            placeholder += create_bracket_product(semicolon[i], True, "#", ";")
        if re.search("rv:", semicolon[len(semicolon) - 1]):
            placeholder += "rv:#"
        else:
            placeholder += create_bracket_product(semicolon[len(semicolon) - 1], True, "#", "")
    return placeholder


def create_bracket_product(semicolon, one, end, separator):
    """Create placeholder for 'products' in brackets. (X; Y; Procuct/12.2; Z) -> ... Product# ...

    Args:
        semicolon (str): String where we try to find product. That mean Product/version.
        one (bool): Return end or original content if semicolon isn't product.
        end (str): End of product

    Returns:
        [type]: [description]
    """
    slash = semicolon.split("/")
    if len(slash) == 1:
        if one is True:
            # replace versions with placeholder
            space = slash[0].split()
            placeholder = ""
            for s in space:
                if re.search("[a-uwyzA-UWYZ]", s):
                    placeholder += f"{s}"
                else:
                    placeholder += "#"
                if s != space[-1]:
                    placeholder += " "
            return f"{placeholder}{separator}"
        return f"{end}{separator}"
    else:
        space = slash[0].split(" ")
        if len(space) != 1:
            if re.search(" [\d]* ", " " + space[1] + " "):
                return f"# {end}{separator}"
            # Mozilla/5.1 (..;124 SM-G900H/15) ... etc.
            search = re.search("(?P<two>[\w]*)-(?P<one>[\w]).*", space[1])
            if search:
                from_search = "{two}-{one}".format(**search.groupdict())
                return f"# {from_search}{end}{separator}"
            return f"# {space[1]}{end}{separator}"
        else:
            if re.search("SAMSUNG-.*", slash[0]):
                return f"SAMSUNG{end}{separator}"
            return f"{slash[0]}{end}{separator}"


def get_another_bracket(string, keywords, start, end):
    """Proces another brackets like clasic useragent brackets ().

    Args:
        string (str): Inside of another brackets.
        keywords (dict): Keywords of OSs for mine_os module.
        start (str): Start symbol of another brackets, like [
        endt (str): End symbol of another brackets, like ]

    Returns:
        str: Placeholder variant of
    """
    placeholder = ""
    s_tmp = False
    start_bracket = string.split(start)
    for i in range(len(start_bracket)):
        end_bracket = start_bracket[i].split(end)
        if len(end_bracket) == 1:
            # Example: P/1 [...] ..., here goes P/1 || ... [X [...] ...] ... and also X in this example
            if i == 0:
                placeholder += get_placeholder_products(end_bracket[0])
            else:
                if s_tmp is False:
                    placeholder += start
                    s_tmp = True
                placeholder += get_placeholder_products(end_bracket[0])
        elif len(end_bracket) == 2:
            # Example: ... [X] P/1, here goes ['X', 'P/1'] list
            if s_tmp is False:
                placeholder += start
                s_tmp = True
            placeholder += f"{get_placeholder_bracket(end_bracket[0], keywords)}{end} "
            placeholder += get_placeholder_products(end_bracket[1])
        else:
            # Example: [X [Y; Z]] -> [X | Y; Z]
            if s_tmp is False:
                placeholder += start
            for j in range(len(end_bracket) - 1):
                placeholder += f"{get_placeholder_bracket(end_bracket[j], keywords)}"
                if i != len(end_bracket) - 1:
                    placeholder += "|"
            placeholder += end
            placeholder += get_placeholder_products(end_bracket[-1])
    return placeholder


def get_placeholder_products(string):
    """Function split string on products and crete for every product his placeholder variant.

    Args:
        string (str): Products part of HTTP useragent.

    Returns:
        str: Placeholder variant of produtct in string as one string.
    """
    placeholder = ""
    # split by space, default of .split() method
    products = string.split()
    for j in range(0, len(products)):
        if re.search("[a-zA-Z]", products[j]):
            tmp = " " + products[j] + " "
            if re.match(" v\d+ ", tmp) or re.match(" t\d+ ", tmp):
                # Mozilla/5.1 ... RuxitSynthetic/10.2 v6086031338 t96946 athc8050e87 altpub -> this type of useragents are in csv database 752 204
                placeholder += "# "
            else:
                placeholder += create_placeholder_for_product(products[j])
        else:
            placeholder += "# "
    return placeholder


def create_placeholder_for_product(product):
    """Create placeholder variant for one single product

    Args:
        product (str): Product from HTTP useragent.

    Returns:
        str: Placehodler variant of given product
    """
    name_version = product.split("/")
    if len(name_version) == 1:
        if re.search("IVW-Crawler-\d*", name_version[0]):
            return f"IVW-Crawler-#"
        return f"{name_version[0]} "
    return f"{name_version[0]}# "
