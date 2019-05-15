# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from typing import Dict, List, Tuple
from defusedxml import ElementTree as ET
import os
import re
from jsonschema import draft4_format_checker

from wazuh import common

_alphanumeric_param = re.compile(r'^[\w,\-\.\+\s\:]+$')
_array_numbers = re.compile(r'^\d+(,\d+)*$')
_array_names = re.compile(r'^[\w\-\.]+(,[\w\-\.]+)*$')
_base64 = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
_boolean = re.compile(r'^true$|^false$')
_cdb_list = re.compile(r'^#?[\w\s-]+:{1}(#?[\w\s-]+|)$')
_dates = re.compile(r'^\d{8}$')
_empty_boolean = re.compile(r'^$|(^true$|^false$)')
_hashes = re.compile(r'^[\da-fA-F]{32}(?:[\da-fA-F]{8})?$|(?:[\da-fA-F]{32})?$')
_ips = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2])){0,1}$|^any$|^ANY$')
_names = re.compile(r'^[\w\-\.]+$')
_numbers = re.compile(r'^\d+$')
_wazuh_key = re.compile(r'[a-zA-Z0-9]+$')
_paths = re.compile(r'^[\w\-\.\\\/:]+$')
_query_param = re.compile(r"^(?:[\w\.\-]+(?:=|!=|<|>|~)[\w\.\- ]+)(?:(?:;|,)[\w\.\-]+(?:=|!=|<|>|~)[\w\.\- ]+)*$")
_ranges = re.compile(r'[\d]+$|^[\d]{1,2}\-[\d]{1,2}$')
_etc_path = re.compile(
    r'(^etc\/ossec.conf$)|((^etc\/rules\/|^etc\/decoders\/)[\w\-\/]+\.{1}xml$|(^etc\/lists\/)[\w\-\.\/]+)$')
_ruleset_path = re.compile(r'(^ruleset\/rules$)|(^ruleset\/decoders$)|(^etc\/rules$)|(^etc\/decoders$)$')
_search_param = re.compile(r'^[^;\|&\^*>]+$')
_sort_param = re.compile(r'^[\w_\-\,\s\+\.]+$')
_timeframe_type = re.compile(r'^(\d{1,}[d|h|m|s]?){1}$')
_type_format = re.compile(r'^xml$|^json$')
_yes_no_boolean = re.compile(r'^yes$|^no$')


def check_exp(exp: str, regex: str) -> bool:
    """
    Function to check if an expression matches a regex
    :param exp: Expression to check
    :param regex: regular expression to do the matching
    :return: True if expression is matched, False otherwise
    """
    if not isinstance(exp, str):
        return True
    return re.match(regex, exp)


def check_xml(xml_string: str) -> bool:
    """
    Function to check if a XML string is right
    :param xml_string: XML string to check
    :return: True if XML is OK, False otherwise
    """
    try:
        ET.fromstring(xml_string)
    except ET.ParseError:
        return False
    except Exception:
        return False

    return True


def check_cdb_list(cdb_list: str) -> bool:
    """
    Function to check if a CDB list is well formed
    :param cdb_list: CDB list to check
    :return: True if CDB list is OK, False otherwise
    """
    cdb_list_splitted = cdb_list.split('\n')
    line = 1

    for elem in cdb_list_splitted:
        if not _cdb_list.match(elem):
            return False
        line += 1

    return True


def allowed_fields(filters: Dict) -> List:
    """
    Returns a list with allowed fields
    :param filters: Dictionary with valid filters
    :return: List with allowed filters
    """
    return [field for field in filters]


def is_safe_path(path: str, basedir: str = common.ossec_path, follow_symlinks: bool = True) -> bool:
    """
    Checks if a path is correct
    :param path: Path to be checked
    :param basedir: Wazuh installation directory
    :param follow_symlinks: True if path is relative, False if it is absolute
    :return: True if path is correct, False otherwise
    """
    # resolves symbolic links
    if follow_symlinks:
        full_path = common.ossec_path + path
        return os.path.realpath(full_path).startswith(basedir)

    return os.path.abspath(path).startswith(basedir)


@draft4_format_checker.checks("alphanumeric")
def format_alphanumeric(value):
    return check_exp(value, _alphanumeric_param)


@draft4_format_checker.checks("base64")
def format_base64(value):
    return check_exp(value, _base64)


@draft4_format_checker.checks("etc_path")
def format_etc_path(relative_path):
    """
    Function to check if a relative path is allowed (for uploading files)
    :param relative_path: XML string to check
    :return: True if XML is OK, False otherwise
    """
    if not is_safe_path(relative_path):
        return False

    return check_exp(relative_path, _etc_path)

@draft4_format_checker.checks("ruleset_path")
def format_relative_ruleset_path(relative_path):
    """
    Function to check if a relative path is allowed
    :param relative_path: string to check
    :return: True if is OK, False otherwise
    """
    if not is_safe_path(relative_path):
        return False

    return check_exp(relative_path, _ruleset_path)

@draft4_format_checker.checks("hash")
def format_hash(value):
    return check_exp(value, _hashes)


@draft4_format_checker.checks("names")
def format_names(value):
    return check_exp(value, _names)


@draft4_format_checker.checks("numbers")
def format_numbers(value):
    return check_exp(value, _numbers)


@draft4_format_checker.checks("path")
def format_path(value):
    return check_exp(value, _paths)


@draft4_format_checker.checks("query")
def format_query(value):
    return check_exp(value, _query_param)


@draft4_format_checker.checks("range")
def format_range(value):
    return check_exp(value, _ranges)


@draft4_format_checker.checks("search")
def format_search(value):
    return check_exp(value, _search_param)


@draft4_format_checker.checks("sort")
def format_sort(value):
    return check_exp(value, _sort_param)


@draft4_format_checker.checks("timeframe")
def format_timeframe(value):
    return check_exp(value, _timeframe_type)


@draft4_format_checker.checks("wazuh_key")
def format_wazuh_key(value):
    return check_exp(value, _wazuh_key)
