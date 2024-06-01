# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from configparser import NoOptionError, RawConfigParser
from io import StringIO
from os import path as os_path
from os import remove
from types import MappingProxyType
from typing import List, Union

from defusedxml.ElementTree import tostring
from defusedxml.minidom import parseString
from wazuh.core import common, wazuh_socket
from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.utils import cut_array, load_wazuh_xml, safe_move

logger = logging.getLogger('wazuh')

# Aux functions

# Type of configuration sections:
#   * Duplicate -> there can be multiple independent sections. Must be returned as multiple json entries.
#   * Merge -> there can be multiple sections but all are dependent with each other. Must be returned as a single json
#   entry.
#   * Last -> there can be multiple sections in the configuration but only the last one will be returned.
#   The rest are ignored.
CONF_SECTIONS = MappingProxyType({
    'active-response': {'type': 'duplicate', 'list_options': []},
    'command': {'type': 'duplicate', 'list_options': []},
    'agentless': {'type': 'duplicate', 'list_options': []},
    'localfile': {'type': 'duplicate', 'list_options': ["filter", "ignore"]},
    'remote': {'type': 'duplicate', 'list_options': []},
    'syslog_output': {'type': 'duplicate', 'list_options': []},
    'integration': {'type': 'duplicate', 'list_options': []},

    'alerts': {'type': 'merge', 'list_options': []},
    'client': {'type': 'merge', 'list_options': []},
    'database_output': {'type': 'merge', 'list_options': []},
    'email_alerts': {
        'type': 'merge',
        'list_options': ['email_to']
    },
    'reports': {
        'type': 'merge',
        'list_options': ['email_to']
    },
    'global': {
        'type': 'merge',
        'list_options': ['white_list']
    },
    'open-scap': {
        'type': 'merge',
        'list_options': ['content']
    },
    'cis-cat': {
        'type': 'merge',
        'list_options': ['content']
    },
    'syscollector': {
        'type': 'merge',
        'list_options': []
    },
    'rootcheck': {
        'type': 'merge',
        'list_options': ['rootkit_files', 'rootkit_trojans', 'windows_audit', 'system_audit', 'windows_apps',
                         'windows_malware']
    },
    'ruleset': {
        'type': 'merge',
        'list_options': ['include', 'rule', 'rule_dir', 'decoder', 'decoder_dir', 'list', 'rule_exclude',
                         'decoder_exclude']
    },
    'syscheck': {
        'type': 'merge',
        'list_options': ['directories', 'ignore', 'nodiff']
    },
    'auth': {
        'type': 'merge',
        'list_options': []
    },

    'cluster': {
        'type': 'last',
        'list_options': ['nodes']
    },
    'osquery': {
        'type': 'merge',
        'list_options': ['pack']
    },
    'labels': {
        'type': 'duplicate',
        'list_options': ['label']
    },
    'sca': {
        'type': 'merge',
        'list_options': ['policies']
    },
    'vulnerability-detection': {
        'type': 'last',
        'list_options': []
    },
    'indexer': {
        'type': 'last',
        'list_options': ['hosts']
    }
})

GETCONFIG_COMMAND = "getconfig"
UPDATE_CHECK_OSSEC_FIELD = 'update_check'
GLOBAL_KEY = 'global'
YES_VALUE = 'yes'
CTI_URL_FIELD = 'cti-url'
DEFAULT_CTI_URL = 'https://cti.wazuh.com'


def _insert(json_dst: dict, section_name: str, option: str, value: str):
    """Insert element (option:value) in a section (json_dst) called section_name.

    Parameters
    ----------
    json_dst : dict
        Destination.
    section_name : str
        Name of the section.
    option : str
        Option to be updated or added.
    value : str
        Value of the option to be updated / added.
    """

    if not value:
        return

    if option in json_dst:
        if type(json_dst[option]) is list:
            json_dst[option].append(value)  # Append new values
        else:
            json_dst[option] = value  # Update values
    else:
        if option in CONF_SECTIONS.get(section_name, {}).get('list_options', []):
            json_dst[option] = [value]  # Create as list
        else:
            json_dst[option] = value  # Update values


def _insert_section(json_dst: dict, section_name: str, section_data: dict):
    """Insert a new section (section_data) called section_name in json_dst.

    Parameters
    ----------
    json_dst : dict
        Destination.
    section_name : str
        Name of the section.
    section_data : dict
        Section be added.
    """

    if CONF_SECTIONS.get(section_name, {}).get('type') == 'duplicate':
        if section_name in json_dst:
            json_dst[section_name].append(section_data)  # Append new values
        else:
            json_dst[section_name] = [section_data]  # Create as list
    elif CONF_SECTIONS.get(section_name, {}).get('type') == 'merge':
        if section_name in json_dst:
            for option in section_data:
                if option in json_dst[section_name] and option in CONF_SECTIONS[section_name].get('list_options', []):
                    json_dst[section_name][option].extend(section_data[option])  # Append new values
                else:
                    json_dst[section_name][option] = section_data[option]  # Update values
        else:
            json_dst[section_name] = section_data  # Create
    elif CONF_SECTIONS.get(section_name, {}).get('type') == 'last':
        if section_name in json_dst:
            # if the option already exists it is overwritten. But a warning is shown.
            logger.warning(f'There are multiple {section_name} sections in configuration. Using only last section.')
        json_dst[section_name] = section_data  # Create


def _read_option(section_name: str, opt: str) -> tuple:
    """Read an option (inside a section) and returns the name and the value.

    Parameters
    ----------
    section_name : str
        Name of the section to be read.
    opt : str
        Option to be read.

    Returns
    -------
    tuple
        Name and value of the option.
    """

    opt_name = opt.tag.lower()

    if section_name == 'open-scap':
        if opt.attrib:
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            # profiles
            profiles_list = []
            for profiles in opt.iter():
                profiles_list.append(profiles.text)

            if profiles_list:
                opt_value['profiles'] = profiles_list
        else:
            opt_value = opt.text
    elif section_name == 'syscheck' and opt_name == 'directories':
        opt_value = []

        json_attribs = {}
        for a in opt.attrib:
            json_attribs[a] = opt.attrib[a]

        if opt.text:
            for path in opt.text.split(','):
                json_path = json_attribs.copy()
                json_path['path'] = path.strip()
                opt_value.append(json_path)
    elif (section_name == 'syscheck' and opt_name in ('synchronization', 'whodata')) or \
        (section_name == 'cluster' and opt_name == 'haproxy_helper'):
        opt_value = {}
        for child in opt:
            child_section, child_config = _read_option(child.tag.lower(), child)
            opt_value[child_section] = child_config.split(',') if child_config.find(',') > 0 else child_config
    elif (section_name == 'cluster' and opt_name == 'nodes') or \
            (section_name == 'haproxy_helper' and opt_name == 'excluded_nodes') or \
            (section_name == 'sca' and opt_name == 'policies') or \
            (section_name == 'indexer' and opt_name == 'hosts')    :
        opt_value = [child.text for child in opt]
    elif section_name == 'labels' and opt_name == 'label':
        opt_value = {'value': opt.text}
        for a in opt.attrib:
            opt_value[a] = opt.attrib[a]
    elif section_name == 'localfile' and opt_name == 'query':
        # Remove new lines, empty spaces and backslashes
        regex = rf'<{opt_name}>(.*)</{opt_name}>'
        opt_value = re.match(regex,
                             re.sub('(?:(\n) +)', '',
                                    tostring(opt, encoding='unicode').replace('\\<', '<').replace('\\>', '>')
                                    ).strip()).group(1)
    elif section_name == 'remote' and opt_name == 'protocol':
        opt_value = [elem.strip() for elem in opt.text.split(',')]
    else:
        if opt.attrib or list(opt):
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            if list(opt):
                for child in opt:
                    child_section, child_config = _read_option(child.tag.lower(), child)
                    try:
                        opt_value[child_section].append(child_config)
                    except KeyError:
                        opt_value[child_section] = [child_config]

            else:
                opt_value['item'] = opt.text
        else:
            opt_value = opt.text

    return opt_name, _replace_custom_values(opt_value)


def _replace_custom_values(opt_value: Union[list, dict, str]) -> Union[list, dict, str]:
    """Replace custom values introduced by 'load_wazuh_xml' with their real values.

    Parameters
    ----------
    opt_value : list or dict or str
        Value to be replaced.
    """
    if type(opt_value) is list:
        for i in range(0, len(opt_value)):
            opt_value[i] = _replace_custom_values(opt_value[i])
    elif type(opt_value) is dict:
        for key in opt_value.keys():
            opt_value[key] = _replace_custom_values(opt_value[key])
    elif type(opt_value) is str:
        return opt_value.replace('_custom_amp_lt_', '&lt;').replace('_custom_amp_gt_', '&gt;')
    return opt_value


def _conf2json(src_xml: str, dst_json: dict):
    """Parse src_xml to JSON. It is inserted in dst_json.

    Parameters
    ----------
    src_xml : str
        Configuration to be parsed to JSON.
    dst_json : dict
        Destination.
    """

    for section in list(src_xml):
        section_name = section.attrib['name'] if section.tag.lower() == 'wodle' else section.tag.lower()
        section_json = {}

        for option in list(section):
            option_name, option_value = _read_option(section_name, option)
            if type(option_value) is list and not (section_name == 'remote' and option_name == 'protocol'):
                for ov in option_value:
                    _insert(section_json, section_name, option_name, ov)
            else:
                _insert(section_json, section_name, option_name, option_value)

        _insert_section(dst_json, section_name, section_json)


def _ossecconf2json(xml_conf: str) -> dict:
    """Return ossec.conf in JSON from XML.

    Parameters
    ----------
    xml_conf : str
        Configuration to be parsed to JSON.

    Returns
    -------
    dict
        Final JSON with the ossec.conf content.
    """
    final_json = {}

    for root in list(xml_conf):
        if root.tag.lower() == "ossec_config":
            _conf2json(root, final_json)

    return final_json


def _agentconf2json(xml_conf: str) -> dict:
    """Return agent.conf in JSON from XML.

    Parameters
    ----------
    xml_conf : str
        Configuration to be parsed to JSON.

    Returns
    -------
    dict
        Final JSON with the agent.conf content.
    """

    final_json = []

    for root in xml_conf.iter():
        if root.tag.lower() == "agent_config":
            # Get attributes (os, name, profile)
            filters = {}
            for attr in root.attrib:
                filters[attr] = root.attrib[attr]

            # Check if we have read the same filters before (we will need to merge them)
            previous_config = -1
            for idx, item in enumerate(final_json):
                if 'filters' in item and item['filters'] == filters:
                    previous_config = idx
                    break

            if previous_config != -1:
                _conf2json(root, final_json[previous_config]['config'])
            else:
                config = {}
                _conf2json(root, config)
                final_json.append({'filters': filters, 'config': config})

    return final_json


def _rcl2json(filepath: str) -> dict:
    """
    Returns the RCL file as dictionary.

    Parameters
    ----------
    filepath : str
        Path to the RCL file.

    Raises
    ------
    WazuhError(1101)
        Requested component does not exist.

    Returns
    -------
    dict
        RCL file (system_audit, windows_audit) as dictionary.
    """

    data = {'vars': {}, 'controls': []}
    # [Application name] [any or all] [reference]
    # type: '<entry name>;'
    regex_comment = re.compile(r"^\s*#")
    regex_title = re.compile(r"^\s*\[(.*)\]\s*\[(.*)\]\s*\[(.*)\]\s*")
    regex_name_groups = re.compile(r"({\w+:\s+\S+\s*\S*\})")
    regex_check = re.compile(r"^\s*(\w:.+)")
    regex_var = re.compile(r"^\s*\$(\w+)=(.+)")

    try:
        item = {}

        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_title = re.search(regex_title, line)
                if match_title:
                    # Previous
                    data['controls'].append(item)

                    # New
                    name = match_title.group(1)
                    condition = match_title.group(2)
                    reference = match_title.group(3)

                    item = {}

                    # Name
                    end_name = name.find('{')
                    item['name'] = name[:end_name].strip()

                    # Extract PCI and CIS from name
                    name_groups = list()
                    name_groups.extend(re.findall(regex_name_groups, name))

                    cis, pci = list(), list()

                    for group in name_groups:
                        # {CIS: 1.1.2 RHEL7}
                        g_value = group.split(':')[-1][:-1].strip()
                        if 'CIS' in group:
                            cis.append(g_value)
                        elif 'PCI' in group:
                            pci.append(g_value)

                    item['cis'] = cis
                    item['pci'] = pci

                    # Conditions
                    if condition:
                        item['condition'] = condition
                    if reference:
                        item['reference'] = reference
                    item['checks'] = []

                    continue

                match_checks = re.search(regex_check, line)
                if match_checks:
                    item['checks'].append(match_checks.group(1))
                    continue

                match_var = re.search(regex_var, line)
                if match_var:
                    data['vars'][match_var.group(1)] = match_var.group(2)
                    continue

            # Last item
            data['controls'].append(item)

    except Exception as e:
        raise WazuhError(1101, str(e))

    return data


def _rootkit_files2json(filepath: str) -> dict:
    """Return the rootkit file as dictionary.

    Parameters
    ----------
    filepath : str
        Path to the rootkit file.

    Raises
    ------
    WazuhError(1101)
        Requested component does not exist.

    Returns
    -------
    dict
        Rootkit file as dictionary.
    """

    data = []

    # file_name ! Name ::Link to it
    regex_comment = re.compile(r"^\s*#")
    regex_check = re.compile(r"^(.+)!(.+)::(.+)")

    try:
        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                if match_check := re.search(regex_check, line):
                    new_check = {'filename': match_check.group(1).strip(), 'name': match_check.group(2).strip(),
                                 'link': match_check.group(3).strip()}
                    data.append(new_check)

    except Exception as e:
        raise WazuhError(1101, str(e))

    return data


def _rootkit_trojans2json(filepath: str) -> dict:
    """Return the rootkit trojans file as dictionary.


    Parameters
    ----------
    filepath : str
        Path to the rootkit trojans file.

    Raises
    ------
    WazuhError(1101)
        Requested component does not exist.

    Returns
    -------
    dict
        Rootkit trojans file as dictionary.
    """

    data = []

    # file_name !string_to_search!Description
    regex_comment = re.compile(r"^\s*#")
    regex_check = re.compile(r"^(.+)!(.+)!(.+)")
    regex_binary_check = re.compile(r"^(.+)!(.+)!")

    try:
        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_check = re.search(regex_check, line)
                match_binary_check = re.search(regex_binary_check, line)
                if match_check:
                    new_check = {'filename': match_check.group(1).strip(), 'name': match_check.group(2).strip(),
                                 'description': match_check.group(3).strip()}
                    data.append(new_check)
                elif match_binary_check:
                    new_check = {'filename': match_binary_check.group(1).strip(),
                                 'name': match_binary_check.group(2).strip()}
                    data.append(new_check)

    except Exception as e:
        raise WazuhError(1101, str(e))

    return data


def _ar_conf2json(file_path: str) -> dict:
    """Return the lines of the ar.conf file.

    Parameters
    ----------
    file_path : str
        Path to the ar.conf file.

    Returns
    -------
    dict
        ar.conf file as dictionary.
    """
    with open(file_path) as f:
        data = [line.strip('\n') for line in f.readlines()]
    return data


def _merged_mg2json(file_path: str) -> List[dict]:
    """Parse the merged.mg file.

    Parameters
    ----------
    file_path : str
        Path to the merged.mg file.

    Returns
    -------
    dict
        merged.mg file as a list of dictionaries.
    """
    data = []

    # ![file_size] [file_name]
    regex_header = re.compile(r"^!(\d+)\s*(.*)")

    try:
        item = {}
        file_content = []

        with open(file_path) as f:
            # Skip first line
            next(f)

            for line in f:
                if match_header := re.search(regex_header, line):
                    if item:
                        # Append previous item
                        item['file_content'] = ''.join(file_content)
                        data.append(item)

                    file_size = match_header.group(1)
                    file_name = match_header.group(2)
                    file_content = []
                    item = {'file_name': file_name, 'file_size': int(file_size)}
                    continue

                file_content.append(line)

        # Append last item
        data.append(item)
    except Exception as e:
        raise WazuhError(1101, str(e))

    return data


# Main functions
def get_ossec_conf(section: str = None, field: str = None, conf_file: str = common.OSSEC_CONF,
                   from_import: bool = False, distinct: bool = False) -> dict:
    """Return ossec.conf (manager) as dictionary.

    Parameters
    ----------
    section : str
        Filters by section (i.e. rules).
    field : str
        Filters by field in section (i.e. included).
    conf_file : str
        Path of the configuration file to read. Default: common.OSSEC_CONF
    from_import : bool
        This flag indicates whether this function has been called from a module load (True) or from a function (False).
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhError(1101)
        Requested component does not exist.
    WazuhError(1102)
        Invalid section.
    WazuhError(1103)
        Invalid field in section.
    WazuhError(1106)
        Requested section not present in configuration.

    Returns
    -------
    dict
        ossec.conf (manager) as dictionary.
    """
    try:
        # Read XML
        xml_data = load_wazuh_xml(conf_file)

        # Parse XML to JSON
        data = _ossecconf2json(xml_data)
    except Exception as e:
        if not from_import:
            raise WazuhError(1101, extra_message=str(e))
        else:
            print(f"wazuh-apid: There is an error in the ossec.conf file: {str(e)}")
            sys.exit(0)

    if section:
        try:
            data = {section: data[section]}
        except KeyError as e:
            if section not in CONF_SECTIONS.keys():
                raise WazuhError(1102, extra_message=e.args[0])
            else:
                raise WazuhError(1106, extra_message=e.args[0])

    if section and field:
        try:
            if isinstance(data[section], list):
                data = {section: [{field: item[field]} for item in data[section]]}
            else:
                field_data = data[section][field]
                if distinct and section == 'ruleset':
                    if field in ('decoder_dir', 'rule_dir'):
                        # Remove duplicates
                        values = []
                        [values.append(x) for x in field_data if x not in values]
                        field_data = values

                data = {section: {field: field_data}}
        except KeyError:
            raise WazuhError(1103)

    return data


def get_agent_conf(group_id: str = None, offset: int = 0, limit: int = common.DATABASE_LIMIT,
                   filename: str = 'agent.conf', raw: bool = False) -> Union[dict, str]:
    """Return agent.conf as dictionary.

    Parameters
    ----------
    group_id : str
        ID of the group with the agent.conf we want to get.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    filename : str
        Name of the file to get. Default: 'agent.conf'
    raw : bool
        Respond in raw format.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1006)
        agent.conf does not exist or there is a problem with the permissions.
    WazuhError(1101)
        Requested component does not exist.

    Returns
    -------
    dict or str
        agent.conf as dictionary.
    """
    if not os_path.exists(os_path.join(common.SHARED_PATH, group_id)):
        raise WazuhResourceNotFound(1710, group_id)
    agent_conf = os_path.join(common.SHARED_PATH, group_id if group_id is not None else '', filename)

    if not os_path.exists(agent_conf):
        raise WazuhError(1006, agent_conf)

    try:
        # Read RAW file
        if filename == 'agent.conf' and raw:
            with open(agent_conf, 'r') as raw_data:
                data = raw_data.read()
                return data
        # Parse XML to JSON
        else:
            # Read XML
            xml_data = load_wazuh_xml(agent_conf)

            data = _agentconf2json(xml_data)
    except Exception as e:
        raise WazuhError(1101, str(e))

    return {'total_affected_items': len(data), 'affected_items': cut_array(data, offset=offset, limit=limit)}


def get_agent_conf_multigroup(multigroup_id: str = None, offset: int = 0, limit: int = common.DATABASE_LIMIT,
                              filename: str = None) -> dict:
    """Return agent.conf as dictionary.

    Parameters
    ----------
    multigroup_id : str
        ID of the group with the agent.conf we want to get.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    filename : str
        Name of the file to get. Default: 'agent.conf'

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1006)
        agent.conf does not exist or there is a problem with the permissions.
    WazuhError(1101)
        Requested component does not exist.

    Returns
    -------
    dict
        agent.conf as dictionary.
    """
    # Check if a multigroup_id is provided and it exists
    if multigroup_id and not os_path.exists(os_path.join(common.MULTI_GROUPS_PATH, multigroup_id)) or not multigroup_id:
        raise WazuhResourceNotFound(1710, extra_message=multigroup_id if multigroup_id else "No multigroup provided")

    agent_conf_name = filename if filename else 'agent.conf'
    agent_conf = os_path.join(common.MULTI_GROUPS_PATH, multigroup_id, agent_conf_name)

    if not os_path.exists(agent_conf):
        raise WazuhError(1006, extra_message=os_path.join("WAZUH_PATH", "var", "multigroups", agent_conf))

    try:
        # Read XML
        xml_data = load_wazuh_xml(agent_conf)

        # Parse XML to JSON
        data = _agentconf2json(xml_data)
    except Exception:
        raise WazuhError(1101)

    return {'totalItems': len(data), 'items': cut_array(data, offset=offset, limit=limit)}


def get_file_conf(filename: str, group_id: str = None, type_conf: str = None, raw: bool = False) -> dict | str:
    """Return the configuration file content.

    Parameters
    ----------
    group_id : str
        ID of the group with the file we want to get.
    filename : str
        Name of the file to get.
    type_conf : str
        Type of the configuration we want to get.
    raw : bool
        Respond in raw format.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1006)
        The file does not exist or there is a problem with the permissions.
    WazuhError(1104)
        Invalid file type.

    Returns
    -------
    dict or str
        File content as plain text or dictionary.
    """
    if not os_path.exists(os_path.join(common.SHARED_PATH, group_id)):
        raise WazuhResourceNotFound(1710, group_id)

    file_path = os_path.join(common.SHARED_PATH, group_id if not filename == 'ar.conf' else '', filename)

    if not os_path.exists(file_path):
        raise WazuhError(1006, file_path)

    if raw:
        with open(file_path, 'r') as raw_data:
            data = raw_data.read()
            return data

    types = {
        'conf': get_agent_conf,
        'rootkit_files': _rootkit_files2json,
        'rootkit_trojans': _rootkit_trojans2json,
        'rcl': _rcl2json
    }

    if type_conf:
        if type_conf in types:
            if type_conf == 'conf':
                data = types[type_conf](group_id, limit=None, filename=filename, raw=raw)
            else:
                data = types[type_conf](file_path)
        else:
            raise WazuhError(1104, f'{type_conf}. Valid types: {types.keys()}')
    else:
        if filename == 'agent.conf':
            data = get_agent_conf(group_id, limit=None, filename=filename, raw=raw)
        elif filename == 'rootkit_files.txt':
            data = _rootkit_files2json(file_path)
        elif filename == 'rootkit_trojans.txt':
            data = _rootkit_trojans2json(file_path)
        elif filename == 'ar.conf':
            data = _ar_conf2json(file_path)
        elif filename == 'merged.mg':
            data = _merged_mg2json(file_path)
        else:
            data = _rcl2json(file_path)

    return data


def parse_internal_options(high_name: str, low_name: str) -> str:
    """Parse internal_options.conf file.

    Parameters
    ----------
    high_name : str
        Name of the daemon with the option we want to parse.
    low_name : str
        Option we want to parse.

    Raises
    ------
    WazuhInternalError(1107)
        Internal options file not found.
    WazuhInternalError(1108)
        Value not found in internal_options.conf.

    Returns
    -------
    str
        Value of the internal_options.conf option.
    """

    def get_config(config_path: str) -> dict:
        """Read configuration given by its path.

        Parameters
        ----------
        config_path : str
            Configuration path.

        Returns
        -------
        dict
            Configuration as a dictionary.
        """
        with open(config_path) as f:
            str_config = StringIO('[root]\n' + f.read())

        config = RawConfigParser()
        config.read_file(str_config)

        return config

    if not os_path.exists(common.INTERNAL_OPTIONS_CONF):
        raise WazuhInternalError(1107)

    # Check if the option exists at local internal options
    if os_path.exists(common.LOCAL_INTERNAL_OPTIONS_CONF):
        try:
            return get_config(common.LOCAL_INTERNAL_OPTIONS_CONF).get('root', f'{high_name}.{low_name}')
        except NoOptionError:
            pass

    try:
        return get_config(common.INTERNAL_OPTIONS_CONF).get('root', f'{high_name}.{low_name}')
    except NoOptionError as e:
        raise WazuhInternalError(1108, e.args[0])


def get_internal_options_value(high_name: str, low_name: str, max_: int, min_: int) -> int:
    """Get value of a specific internal option from internal_options.conf.

    Parameters
    ----------
    high_name : str
        Name of the daemon with the option we want to get.
    low_name : str
        Option we want to get.
    max_ : int
        Maximum value of the option.
    min_ : int
        Minimum value of the option.

    Raises
    ------
    WazuhError(1109)
        Option must be a digit.
    WazuhError(1110)
        Option value is out of the limits.

    Returns
    -------
    int
        Value of the internal_options.conf option.
    """
    option = parse_internal_options(high_name, low_name)
    if not option.isdigit():
        raise WazuhError(1109, f'Option: {high_name}.{low_name}. Value: {option}')

    option = int(option)
    if option < min_ or option > max_:
        raise WazuhError(1110, f'Max value: {max_}. Min value: {min_}. Found: {option}.')

    return option


def upload_group_configuration(group_id: str, file_content: str) -> str:
    """Update group configuration.

    Parameters
    ----------
    group_id : str
        Group to update.
    file_content : str
        File content of the new configuration in a string.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1113)
        XML syntax error.
    WazuhError(1114)
        Wazuh syntax error.
    WazuhError(1115)
        Error executing verify-agent-conf.
    WazuhInternalError(1743)
        Error running Wazuh syntax validator.
    WazuhInternalError(1016)
        Error moving file.

    Returns
    -------
    str
        Confirmation message.
    """
    if not os_path.exists(os_path.join(common.SHARED_PATH, group_id)):
        raise WazuhResourceNotFound(1710, group_id)
    # path of temporary files for parsing xml input
    handle, tmp_file_path = tempfile.mkstemp(prefix='api_tmp_file_', suffix='.xml', dir=common.OSSEC_TMP_PATH)
    # create temporary file for parsing xml input and validate XML format
    try:
        with open(handle, 'w') as tmp_file:
            custom_entities = {
                '_custom_open_tag_': '\\<',
                '_custom_close_tag_': '\\>',
                '_custom_amp_lt_': '&lt;',
                '_custom_amp_gt_': '&gt;'
            }

            # Replace every custom entity
            for character, replacement in custom_entities.items():
                file_content = re.sub(replacement.replace('\\', '\\\\'), character, file_content)

            # Beautify xml file using a defusedxml.minidom.parseString
            xml = parseString(f'<root>\n{file_content}\n</root>')

            # Remove first line (XML specification: <? xmlversion="1.0" ?>), <root> and </root> tags, and empty lines
            pretty_xml = '\n'.join(filter(lambda x: x.strip(), xml.toprettyxml(indent='  ').split('\n')[2:-2])) + '\n'

            # Revert xml.dom replacements and remove any whitespaces and '\n' between '\' and '<' if present
            # github.com/python/cpython/blob/8e0418688906206fe59bd26344320c0fc026849e/Lib/xml/dom/minidom.py#L305
            pretty_xml = re.sub(r'(?:(?<=\\) +)', '', pretty_xml.replace("&amp;", "&").replace("&lt;", "<")
                                .replace("&quot;", "\"", ).replace("&gt;", ">").replace("\\\n", "\\"))

            # Restore the replaced custom entities
            for replacement, character in custom_entities.items():
                pretty_xml = re.sub(replacement, character.replace('\\', '\\\\'), pretty_xml)

            tmp_file.write(pretty_xml)
    except Exception as e:
        raise WazuhError(1113, str(e))

    try:
        # check Wazuh xml format
        try:
            subprocess.check_output([os_path.join(common.WAZUH_PATH, "bin", "verify-agent-conf"), '-f', tmp_file_path],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            # extract error message from output.
            # Example of raw output
            # 2019/01/08 14:51:09 verify-agent-conf: ERROR: (1230):
            # Invalid element in the configuration: 'agent_conf'.\n2019/01/08 14:51:09 verify-agent-conf: ERROR: (1207):
            # Syscheck remote configuration in '/var/ossec/tmp/api_tmp_file_2019-01-08-01-1546959069.xml' is corrupted.
            # \n\n
            # Example of desired output:
            # Invalid element in the configuration: 'agent_conf'.
            # Syscheck remote configuration in '/var/ossec/tmp/api_tmp_file_2019-01-08-01-1546959069.xml' is corrupted.
            output_regex = re.findall(pattern=r"\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} verify-agent-conf: ERROR: "
                                              r"\(\d+\): ([\w \/ \_ \- \. ' :]+)", string=e.output.decode())
            if output_regex:
                raise WazuhError(1114, ' '.join(output_regex))
            else:
                raise WazuhError(1115, e.output.decode())
        except Exception as e:
            raise WazuhInternalError(1743, str(e))

        # move temporary file to group folder
        try:
            new_conf_path = os_path.join(common.SHARED_PATH, group_id, "agent.conf")
            safe_move(tmp_file_path, new_conf_path, ownership=(common.wazuh_uid(), common.wazuh_gid()),
                      permissions=0o660)
        except Exception as e:
            raise WazuhInternalError(1016, extra_message=str(e))

        return 'Agent configuration was successfully updated'
    except Exception as e:
        # remove created temporary file
        if os.path.exists(tmp_file_path):
            remove(tmp_file_path)
        raise e


def upload_group_file(group_id: str, file_data: str, file_name: str = 'agent.conf') -> str:
    """Update a group file.

    Parameters
    ----------
    group_id : str
        Group to update.
    file_data : str
        Upload data.
    file_name : str
        File name to update. Default: 'agent.conf'

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1112)
        Empty files are not supported.
    WazuhError(1111)
        Remote group file updates are only available in 'agent.conf' file.

    Returns
    -------
    str
        Confirmation message in string.
    """
    # Check if the group exists
    if not os_path.exists(os_path.join(common.SHARED_PATH, group_id)):
        raise WazuhResourceNotFound(1710, group_id)

    if file_name == 'agent.conf':
        if len(file_data) == 0:
            raise WazuhError(1112)

        return upload_group_configuration(group_id, file_data)
    else:
        raise WazuhError(1111)


def get_active_configuration(agent_id: str, component: str, configuration: str) -> dict:
    """Get an agent's component active configuration.

    Parameters
    ----------
    agent_id : str
        Agent ID. All possible values from 000 onwards.
    component : str
        Selected agent's component.
    configuration : str
        Configuration to get, written on disk.

    Raises
    ------
    WazuhError(1307)
        If the component or configuration are not specified.
    WazuhError(1101)
        If the specified component is not valid.
    WazuhError(1121)
        If the component is not properly configured.
    WazuhInternalError(1121)
        If the socket cant be created.
    WazuhInternalError(1118)
        If the socket is not able to receive a response.
    WazuhError(1117)
        If there's no such file or directory in agent node, or the socket cannot send the request.
    WazuhError(1116)
        If the reply from the node contains an error.

    Returns
    -------
    dict
        The active configuration the agent is currently using.
    """
    sockets_json_protocol = {'remote', 'analysis', 'wdb'}
    component_socket_mapping = {'agent': 'analysis', 'agentless': 'agentless', 'analysis': 'analysis', 'auth': 'auth',
                                'com': 'com', 'csyslog': 'csyslog', 'integrator': 'integrator',
                                'logcollector': 'logcollector', 'mail': 'mail', 'monitor': 'monitor',
                                'request': 'remote', 'syscheck': 'syscheck', 'wazuh-db': 'wdb', 'wmodules': 'wmodules'}
    component_socket_dir_mapping = {'agent': 'sockets', 'agentless': 'sockets', 'analysis': 'sockets',
                                    'auth': 'sockets', 'com': 'sockets', 'csyslog': 'sockets', 'integrator': 'sockets',
                                    'logcollector': 'sockets', 'mail': 'sockets', 'monitor': 'sockets',
                                    'request': 'sockets', 'syscheck': 'sockets', 'wazuh-db': 'db',
                                    'wmodules': 'sockets'}

    if not component or not configuration:
        raise WazuhError(1307)

    # Check if the component is correct
    components = component_socket_mapping.keys()
    if component not in components:
        raise WazuhError(1101, f'Valid components: {", ".join(components)}')

    def get_active_configuration_manager():
        """Get manager active configuration."""
        # Communicate with the socket that corresponds to the component requested
        dest_socket = os_path.join(common.WAZUH_PATH, "queue", component_socket_dir_mapping[component],
                                   component_socket_mapping[component])

        # Verify component configuration
        if not os.path.exists(dest_socket):
            raise WazuhError(1121,
                             extra_message=f"Please verify that the component '{component}' is properly configured")

        # Simple socket message
        if component_socket_mapping[component] not in sockets_json_protocol:
            msg = f"{GETCONFIG_COMMAND} {configuration}"

            # Socket connection
            try:
                s = wazuh_socket.WazuhSocket(dest_socket)
            except WazuhInternalError:
                raise
            except Exception as unhandled_exc:
                raise WazuhInternalError(1121, extra_message=str(unhandled_exc))

            # Send message
            s.send(msg.encode())

            # Receive response
            try:
                # Receive data length
                rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
            except ValueError:
                raise WazuhInternalError(1118, extra_message="Data could not be received")
            finally:
                s.close()

            return rec_msg_ok, rec_msg

        # JSON socket message
        else:  # component_socket_mapping[component] in sockets_json_protocol
            msg = wazuh_socket.create_wazuh_socket_message(origin={'module': common.origin_module.get()},
                                                           command=GETCONFIG_COMMAND,
                                                           parameters={'section': configuration})

            # Socket connection
            try:
                s = wazuh_socket.WazuhSocketJSON(dest_socket)
            except WazuhInternalError:
                raise
            except Exception as unhandled_exc:
                raise WazuhInternalError(1121, extra_message=str(unhandled_exc))

            # Send message
            s.send(msg)

            # Receive response
            try:
                response = s.receive(raw=True)
            except ValueError:
                raise WazuhInternalError(1118, extra_message="Data could not be received")
            finally:
                s.close()

            return response['error'], response['data']

    def get_active_configuration_agent():
        """Get agent active configuration"""
        # Always communicate with remote socket
        dest_socket = common.REMOTED_SOCKET

        # Simple socket message
        msg = f"{str(agent_id).zfill(3)} {component} {GETCONFIG_COMMAND} {configuration}"

        # Socket connection
        try:
            s = wazuh_socket.WazuhSocket(dest_socket)
        except WazuhInternalError:
            raise
        except Exception as unhandled_exc:
            raise WazuhInternalError(1121, extra_message=str(unhandled_exc))

        # Send message
        s.send(msg.encode())

        # Receive response
        try:
            # Receive data length
            rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
        except ValueError:
            raise WazuhInternalError(1118, extra_message="Data could not be received")
        finally:
            s.close()

        return rec_msg_ok, rec_msg

    rec_error, rec_data = get_active_configuration_agent() if agent_id != '000' else get_active_configuration_manager()

    if rec_error == 'ok' or rec_error == 0:
        data = json.loads(rec_data) if isinstance(rec_data, str) else rec_data

        # Include password if auth->use_password enabled and authd.pass file exists
        if data.get('auth', {}).get('use_password') == 'yes':
            try:
                with open(os_path.join(common.WAZUH_PATH, "etc", "authd.pass"), 'r') as f:
                    data['authd.pass'] = f.read().rstrip()
            except IOError:
                pass

        return data
    else:
        raise WazuhError(1117 if "No such file or directory" in rec_data or "Cannot send request" in rec_data else 1116,
                         extra_message=f'{component}:{configuration}')


def write_ossec_conf(new_conf: str):
    """Replace the current wazuh configuration (ossec.conf) with the provided configuration.

    Parameters
    ----------
    new_conf : str
        The new configuration to be applied.

    Raises
    ------
    WazuhError(1126)
        Error updating ossec configuration.
    """
    try:
        with open(common.OSSEC_CONF, 'w') as f:
            f.writelines(new_conf)
    except Exception as e:
        raise WazuhError(1126, extra_message=str(e))


def update_check_is_enabled() -> bool:
    """Read the ossec.conf and check UPDATE_CHECK_OSSEC_FIELD value.

    Returns
    -------
    bool
        True if UPDATE_CHECK_OSSEC_FIELD is 'yes' or isn't present, else False.
    """
    try:
        global_configurations = get_ossec_conf(section=GLOBAL_KEY).get(GLOBAL_KEY, {})
        return global_configurations.get(UPDATE_CHECK_OSSEC_FIELD, YES_VALUE) == YES_VALUE
    except WazuhError as e:
        if e.code != 1106:
            raise e
        return True


def get_cti_url() -> str:
    """Get the CTI service URL from the configuration.

    Returns
    -------
    str
        CTI service URL. The default value is returned if CTI_URL_FIELD isn't present.
    """
    try:
        return get_ossec_conf(section=GLOBAL_KEY).get(GLOBAL_KEY, {}).get(CTI_URL_FIELD, DEFAULT_CTI_URL)
    except WazuhError as e:
        if e.code != 1106:
            raise e
        return DEFAULT_CTI_URL
