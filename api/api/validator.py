# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from typing import Dict, List

from defusedxml import ElementTree as ET
from jsonschema import draft4_format_checker

from wazuh.core import common

_alphanumeric_param = re.compile(r'^[\w,\-\.\+\s\:]+$')
_symbols_alphanumeric_param = re.compile(r'^[a-zA-Z0-9_,<>!\-.+\s:/()\'"|=]+$')
_array_numbers = re.compile(r'^\d+(,\d+)*$')
_array_names = re.compile(r'^[\w\-\.%]+(,[\w\-\.%]+)*$')
_base64 = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
_boolean = re.compile(r'^true$|^false$')
_cdb_list = re.compile(r'^#?[\w\s-]+:{1}(#?[\w\s-]+|)$')
_dates = re.compile(r'^\d{8}$')
_empty_boolean = re.compile(r'^$|(^true$|^false$)')
_group_names = re.compile(r'^[A-Za-z0-9.\-_]+\b(?<!\ball)$')
_group_names_delete = re.compile(r'^[A-Za-z0-9.\-_]+$')
_hashes = re.compile(r'^(?:[\da-fA-F]{32})?$|(?:[\da-fA-F]{40})?$|(?:[\da-fA-F]{56})?$|(?:[\da-fA-F]{64})?$|(?:[\da-fA-F]{96})?$|(?:[\da-fA-F]{128})?$')
_ips = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2])){0,1}$|^any$|^ANY$')
_iso8601_date = (r'^([0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])$')
_iso8601_date_time = (
    r'^([0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])[tT](2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?([zZ]|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])$')
_names = re.compile(r'^[\w\-\.%]+$')
_numbers = re.compile(r'^\d+$')
_numbers_delete = re.compile(r'^\d+|all$')
_wazuh_key = re.compile(r'[a-zA-Z0-9]+$')
_paths = re.compile(r'^[\w\-\.\\\/:]+$')
_query_param = re.compile(r"^(?:[\w\.\-]+(?:=|!=|<|>|~)[\w\.\- ]+)(?:(?:;|,)[\w\.\-]+(?:=|!=|<|>|~)[\w\.\- ]+)*$")
_ranges = re.compile(r'[\d]+$|^[\d]{1,2}\-[\d]{1,2}$')
_get_dirnames_path = re.compile(r'^(((etc|ruleset)\/(decoders|rules)[\w\-\/]*)|(etc\/lists[\w\-\/]*))$')
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


def allowed_fields(filters: Dict) -> List:
    """
    Returns a list with allowed fields
    :param filters: Dictionary with valid filters
    :return: List with allowed filters
    """
    return [field for field in filters]


def is_safe_path(path: str, basedir: str = common.ossec_path, relative: bool = True) -> bool:
    """
    Checks if a path is correct
    :param path: Path to be checked
    :param basedir: Wazuh installation directory
    :param relative: True if path is relative, False if it is absolute
    :return: True if path is correct, False otherwise
    """
    # Protect path
    if './' in path or '../' in path:
        return False

    # Resolve symbolic links if present
    full_path = os.path.realpath(os.path.join(basedir, path.lstrip("/")) if relative else path)
    full_basedir = os.path.abspath(basedir)

    return os.path.commonpath([full_path, full_basedir]) == full_basedir


@draft4_format_checker.checks("alphanumeric")
def format_alphanumeric(value):
    return check_exp(value, _alphanumeric_param)


@draft4_format_checker.checks("alphanumeric_symbols")
def format_alphanumeric_symbols(value):
    return check_exp(value, _symbols_alphanumeric_param)


@draft4_format_checker.checks("base64")
def format_base64(value):
    return check_exp(value, _base64)


@draft4_format_checker.checks("get_dirnames_path")
def format_get_dirnames_path(relative_path):
    """
    Function to check if a relative path is allowed to be read
    :param relative_path: path string to check
    :return: True if path is OK, False otherwise
    """
    if not is_safe_path(relative_path):
        return False

    return check_exp(relative_path, _get_dirnames_path)


@draft4_format_checker.checks("hash")
def format_hash(value):
    return check_exp(value, _hashes)


@draft4_format_checker.checks("names")
def format_names(value):
    return check_exp(value, _names)


@draft4_format_checker.checks("numbers")
def format_numbers(value):
    return check_exp(value, _numbers)


@draft4_format_checker.checks("numbers_delete")
def format_numbers_delete(value):
    return check_exp(value, _numbers_delete)


@draft4_format_checker.checks("path")
def format_path(value):
    if not is_safe_path(value):
        return False
    return check_exp(value, _paths)


@draft4_format_checker.checks("wazuh_path")
def format_wazuh_path(value):
    if not is_safe_path(value, relative=False):
        return False
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


@draft4_format_checker.checks("date")
def format_date(value):
    return check_exp(value, _iso8601_date)


@draft4_format_checker.checks("date-time")
def format_datetime(value):
    return check_exp(value, _iso8601_date_time)


@draft4_format_checker.checks("hash_or_empty")
def format_hash_or_empty(value):
    return True if value == "" else format_hash(value)


@draft4_format_checker.checks("names_or_empty")
def format_names_or_empty(value):
    return True if value == "" else format_names(value)


@draft4_format_checker.checks("numbers_or_empty")
def format_numbers_or_empty(value):
    return True if value == "" else format_numbers(value)


@draft4_format_checker.checks("date-time_or_empty")
def format_datetime_or_empty(value):
    return True if value == "" else format_datetime(value)


@draft4_format_checker.checks("group_names")
def format_group_names(value):
    return check_exp(value, _group_names)


@draft4_format_checker.checks("group_names_delete")
def format_group_names_delete(value):
    return check_exp(value, _group_names_delete)
