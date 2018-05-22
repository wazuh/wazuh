#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import operator
from functools import reduce
from collections import OrderedDict
from sys import version_info
if version_info.major == 3:
    unicode = str

from wazuh.exception import WazuhException


def _check_regex(regex_str, expression):
    """
    Checks if expression variable matches a regex
    :param regex_str: regex to match
    :param expression: expression to match
    :return: True or False
    """
    regex = re.compile(regex_str)
    matching = regex.match(expression)
    if matching:
        return matching.group() == expression
    else:
        return False


def _check_list(func, expr_list):
    """
    Check if all elements in a list matches the expression
    :param func: function that returns true or false
    :param expr_list: list of items to match
    :return: True or False
    """
    if not isinstance(expr_list, list):
        return False
    else:
        return reduce(operator.mul, map(lambda x: func(x), expr_list))


def _check_dict(check_dict, checks):
    """
    Checks if a dictionary is correct.

    :param check_dict: dictionary to check
    :param checks: dictionary that defines the checks. It must have the same keys as check_dict, but each value must be the expected type.
    :return: True or False
    """
    def sort_by_keys(input_dict):
        return OrderedDict(sorted(input_dict.items(), key=lambda t: t[0]))

    # if both dictionaries have the same keys, sort them by key
    try:
        intersection = check_dict.viewkeys() & checks.viewkeys()
    except AttributeError: # python3
        intersection = check_dict.keys() & checks.keys()

    if len(intersection) == len(check_dict) == len(checks):
        check_dict = sort_by_keys(check_dict)
        checks = sort_by_keys(checks)
        return list(map(type, check_dict.values())) == list(checks.values())
    else:
        return False # If the intersection doesn't have the same length, they don't have the same fields


def check_length(expression, length=100, func=operator.lt):
    """
    Compares expression length
    :param expression: expression to measure length
    :param length: length to compare
    :param func: operator to compare (default: <)
    :return: True or False
    """
    return func(len(expression), length)


def check_name(name):
    """
    Checks the expression variable is a correct name

    :param name: name to check. Can be None.
    :return: True or Exception
    """
    if name and not _check_regex(regex_str="\w+", expression=name):
        raise WazuhException(4000, 'name')
    else:
        return True


def check_number(number):
    """
    Checks the number variable is a correct number

    :param number: number to check
    :return: True or False
    """
    if number and not _check_regex(regex_str="\d+", expression=str(number)):
        raise WazuhException(4000,'number')
    else:
        return True


def check_path(path):
    """
    Checks the variable path is a correct path

    :param path: path to validate
    :return: True or False
    """
    return _check_regex(regex_str=r"^[a-zA-Z0-9\-\_\.\\\/:]+$", expression=path)


def check_date(date):
    """
    Checks the date variable is a correct date

    :param date: date to check
    :return: True or False
    """
    return _check_regex(regex_str="^\d{8}$", expression=date)


def check_ip(ip):
    """
    Checks the ip variable is a correct ip

    :param ip: ip to check. Can be none.
    :return: True or False
    """
    if ip and not _check_regex(regex_str=r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2])){0,1}$|^any$|^ANY$", expression=ip):
        raise WazuhException(4000,'ip')
    else:
        return False


def check_alphanumeric_param(alphanumeric):
    """
    Check if the parameter is alphanumeric

    :param alphanumeric: param to check
    :return: True or False
    """
    return _check_regex(regex_str=r"^[a-zA-Z0-9_\-\.\+\s]+$", expression=alphanumeric)


def check_range_param(ranges):
    """
    Check if the parameter is a valid range

    :param ranges: range to check
    :return: True or False
    """
    return _check_regex(regex_str=r"^[0-9]+$|^[0-9]{1,2}\-[0-9]{1,2}$", expression=ranges)


def check_hashes(hash):
    """
    Check if the parameter is a valid hash

    :param hash: hash to check
    :return: True or False
    """
    return _check_regex(regex_str=r"^[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?$", expression=hash)


def check_ossec_key(key):
    """
    Check if the parameter is a valid ossec key

    :param key: key to check. Can be none
    :return: True or False
    """
    if key and not _check_regex(regex_str=r"^[a-zA-Z0-9]+$", expression=key):
        raise WazuhException(4000, 'key')
    else:
        return True


def check_timeframe(timeframe):
    """
    Check if the parameter is a valid timeframe

    :param timeframe: timeframe to check
    :return: True or False
    """
    if not _check_regex(regex_str=r"^((\d{1,}[d]){0,1}(\d{1,}[h]){0,1}(\d{1,}[m]){0,1}(\d{1,}[s]){0,1}){1}$|^\d{1,}$", expression=timeframe):
        raise WazuhException(4000, 'timeframe')


def check_sort_param(sort_param):
    """
    Check if the sort parameter is valid

    :param sort_param: param to check. Can be None
    :return: True or False
    """
    if sort_param:
        sort_param['order'] = unicode(sort_param['order'])
        if not _check_dict(check_dict=sort_param, checks={'fields':list, 'order':unicode}):
            raise WazuhException(4000, 'sort')


def check_select_param(select_param):
    """
    Check if the sort parameter is valid

    :param select_param: param to check. Can be None
    :return: None or Exception
    """
    if select_param and not _check_dict(check_dict=select_param, checks={'fields': list}):
        raise WazuhException(4000, 'select')


def check_search_param(search_param):
    """
    Check if the sort parameter is valid

    :param search_param: param to check. Can be None
    :return: None or Exception
    """
    if search_param:
        search_param['value'] = unicode(search_param['value'])
        if not _check_dict(check_dict=search_param, checks={'value': unicode, 'negation': int}):
            raise WazuhException(4000, 'search')


def array_numbers(expr_list):
    """
    Checks if each element of an array is a number

    :return: True or False
    """
    return _check_list(func=check_number, expr_list=expr_list)


def array_names(expr_list):
    """
    Checks if each element of the array is a name

    :param expr_list: list of names to match
    :return: True or False
    """
    return _check_list(func=check_name, expr_list=expr_list)


def group(group_name):
    """
    function to validate the name of a group.

    :param group_name: group name to validate
    :return: Returns True if the input name is valid and False otherwise
    """

    if isinstance(group_name, list):
        return _check_list(func=lambda x: check_length(x) and check_name(x), expr_list=group_name)
    else:
        return check_length(group_name) and check_name(group_name)
