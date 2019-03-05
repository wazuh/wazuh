# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
from xml.etree import ElementTree as ET
import os
import re

from wazuh import common


regex_dict = {'alphanumeric_param': r'^[\w,\-\.\+\s\:]+$',
              'array_numbers': r'^\d+(,\d+)*$',
              'array_names': r'^[\w\-\.]+(,[\w\-\.]+)*$',
              'boolean': r'^true$|^false$',
              'cdb_list': r'^#?[\w\s-]+:{1}(#?[\w\s-]+|)$',
              'dates': r'^\d{8}$',
              'empty_boolean': r'^$|(^true$|^false$)',
              'hashes': r'^[\da-fA-F]{32}(?:[\da-fA-F]{8})?$|(?:[\da-fA-F]{32})?$',
              'ips': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2])){0,1}$|^any$|^ANY$',
              'names': r'^[\w\-\.]+$',
              'numbers': r'^\d+$',
              'ossec_key': r'[a-zA-Z0-9]+$',
              'paths': r'^[\w\-\.\\\/:]+$',
              'query_param': r'[\w ]+$',
              'ranges': r'[\d]+$|^[\d]{1,2}\-[\d]{1,2}$',
              'relative_paths': r'(^etc\/ossec.conf$)|((^etc\/rules\/|^etc\/decoders\/)[\w\-\/]+\.{1}xml$|(^etc\/lists\/)[\w\-\.\/]+)$',
              'search_param': r'^[^;\|&\^*>]+$',
              'select_param': r'^[\w\,\.]+$',
              'sort_param': r'^[\w_\-\,\s\+\.]+$',
              'timeframe_type': r'^(\d{1,}[d|h|m|s]?){1}$',
              'type_format': r'^xml$|^json$',
              'yes_no_boolean': r'^yes$|^no$'
             }


def check_params(parameters, filters):
    """
    Function to check multiple parameters
    :param parameters: Dictionary with parameters to be checked
    :param filters: Dictionary with filters for checking parameters
    :return: True if parameters are OK, False otherwise
    """
    for key in parameters:
        if key not in filters or not check_exp(parameters[key], filters[key]):
            return False

    return True


def check_exp(exp, regex_name):
    """
    Function to check if an expression matches a regex
    :param exp: Expression to check
    :param regex_name: Name of regular expression to do the matching
    :return: True if expression is matched, False otherwise
    """
    return True if re.match(regex_dict[regex_name], exp) else False


def check_path(relative_path):
    """
    Function to check if a relative path is allowed (for uploading files)
    :param relative_path: XML string to check
    :return: True if XML is OK, False otherwise
    """
    if not is_safe_path(relative_path):
        return False

    return check_exp(relative_path, 'relative_paths')


def check_xml(xml_string):
    """
    Function to check if a XML string is right
    :param xml_string: XML string to check
    :return: True if XML is OK, False otherwise
    """
    try:
        ET.fromstring(xml_string)
    except ET.ParseError:
        return False
    
    return True


def check_cdb_list(cdb_list):
    """
    Function to check if a CDB list is well formed
    :param cdb_list: CDB list to check
    :return: True if CDB list is OK, False otherwise
    """
    cdb_list_splitted = cdb_list.split('\n')
    regex = re.compile(regex_dict['cdb_list'])
    line = 1

    for elem in cdb_list_splitted:
        if not regex.match(elem):
            return False
        line += 1
    
    return True


def allowed_fields(filters):
    """
    Returns a list with allowed fields
    :param filters: Dictionary with valid filters
    :return: List with allowed filters
    """
    return [field for field in filters]


def is_safe_path(path, basedir=common.ossec_path, follow_symlinks=True):
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

