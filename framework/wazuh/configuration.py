#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from xml.etree.ElementTree import fromstring
from os import listdir, path as os_path
import re
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh import common
from wazuh.utils import cut_array

# Aux functions

conf_sections = {
    'active-response': { 'type': 'duplicate', 'list_options': [] },
    'command': { 'type': 'duplicate', 'list_options': [] },
    'agentless': { 'type': 'duplicate', 'list_options': [] },
    'localfile': { 'type': 'duplicate', 'list_options': [] },
    'remote': { 'type': 'duplicate', 'list_options': [] },
    'syslog_output': { 'type': 'duplicate', 'list_options': [] },

    'alerts': { 'type': 'simple', 'list_options': [] },
    'client': { 'type': 'simple', 'list_options': [] },
    'database_output': { 'type': 'simple', 'list_options': [] },
    'email_alerts': { 'type': 'simple', 'list_options': [] },
    'reports': { 'type': 'simple', 'list_options': [] },
    'global': {
        'type': 'simple',
        'list_options': ['white_list']
    },
    'open-scap': {
        'type': 'simple',
        'list_options': ['content']
    },
    'rootcheck': {
        'type': 'simple',
        'list_options': ['rootkit_files', 'rootkit_trojans', 'windows_audit', 'system_audit', 'windows_apps', 'windows_malware']
    },
    'ruleset': {
        'type': 'simple',
        'list_options':  ['include', 'rule', 'rule_dir', 'decoder', 'decoder_dir', 'list', 'rule_exclude', 'decoder_exclude']
    },
    'syscheck': {
        'type': 'simple',
        'list_options': ['directories', 'ignore', 'nodiff']
    }
}


def _insert(json_dst, section_name, option, value):
    """
    Inserts element (option:value) in a section (json_dst) called section_name
    """

    if not value:
        return

    if option in json_dst:
        if type(json_dst[option]) is list:
            json_dst[option].append(value)  # Append new values
        else:
            json_dst[option] = value  # Update values
    else:
        if section_name in conf_sections and option in conf_sections[section_name]['list_options']:
            json_dst[option] = [value]  # Create as list
        else:
            json_dst[option] = value  # Update values


def _insert_section(json_dst, section_name, section_data):
    """
    Inserts a new section (section_data) called section_name in json_dst.
    """

    if section_name in conf_sections and conf_sections[section_name]['type'] == 'duplicate':
        if section_name in json_dst:
            json_dst[section_name].append(section_data)  # Append new values
        else:
            json_dst[section_name] = [section_data]  # Create as list
    elif section_name in conf_sections and conf_sections[section_name]['type'] == 'simple':
        if section_name in json_dst:
            for option in section_data:
                if option in json_dst[section_name] and option in conf_sections[section_name]['list_options']:
                    json_dst[section_name][option].extend(section_data[option])  # Append new values
                else:
                    json_dst[section_name][option] = section_data[option]  # Update values
        else:
            json_dst[section_name] = section_data  # Create


def _read_option(section_name, opt):
    """
    Reads an option (inside a section) and returns the name and the value.
    """

    opt_name = opt.tag.lower()

    if section_name == 'open-scap':
        if opt.attrib:
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            # profiles
            profiles_list = []
            for profiles in opt.getchildren():
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

        for path in opt.text.split(','):
            json_path = {}
            json_path = json_attribs.copy()
            json_path['path'] = path.strip()
            opt_value.append(json_path)
    else:
        if opt.attrib:
            opt_value = {}
            opt_value['item'] = opt.text
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
        else:
            opt_value = opt.text

    return opt_name, opt_value


def _conf2json(src_xml, dst_json):
    """
    Parses src_xml to json. It is inserted in dst_json.
    """

    for section in src_xml.getchildren():
        section_name = 'open-scap' if section.tag.lower() == 'wodle' else section.tag.lower()
        section_json = {}

        for option in section.getchildren():
            option_name, option_value = _read_option(section_name, option)
            if type(option_value) is list:
                for ov in option_value:
                    _insert(section_json, section_name, option_name, ov)
            else:
                _insert(section_json, section_name, option_name, option_value)

        _insert_section(dst_json, section_name, section_json)


def _ossecconf2json(xml_conf):
    """
    Returns ossec.conf in JSON from xml
    """
    final_json = {}

    for root in xml_conf.getchildren():
        if root.tag.lower() == "ossec_config":
            _conf2json(root, final_json)

    return final_json


def _agentconf2json(xml_conf):
    """
    Returns agent.conf in JSON from xml
    """

    final_json = []

    for root in xml_conf.getchildren():
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


def _rcl2json(filepath):
    """
    Returns the RCL file as dictionary.

    :return: rcl file (system_audit, windows_audit) as dictionary.
    """

    data = {'vars': {}, 'controls': []}
    # [Application name] [any or all] [reference]
    # type:<entry name>;
    regex_comment = re.compile("^\s*#")
    regex_title = re.compile("^\s*\[(.*)\]\s*\[(.*)\]\s*\[(.*)\]\s*")
    regex_name_groups = re.compile("(\{\w+:\s+\S+\s*\S*\})")
    regex_check = re.compile("^\s*(\w:.+)")
    regex_var = re.compile("^\s*\$(\w+)=(.+)")

    try:
        item = {}

        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_title = re.search(regex_title, line)
                if match_title:
                    # Previous
                    if item:
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
                    name_groups = re.findall(regex_name_groups, name)

                    cis = []
                    pci = []
                    if name_groups:

                        for group in name_groups:
                            # {CIS: 1.1.2 RHEL7}
                            g_value = group.split(':')[-1][:-1].strip()
                            if 'CIS' in group:
                                 cis.append(g_value)
                            elif 'PCI' in group:
                                 pci.append(g_value)

                    if cis:
                        item['cis'] = cis
                    if pci:
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
        raise WazuhException(1101, str(e))

    return data


def _rootkit_files2json(filepath):
    """
    Returns the rootkit file as dictionary.

    :return: rootkit file as dictionary.
    """

    data = []

    # file_name ! Name ::Link to it
    regex_comment = re.compile("^\s*#")
    regex_check = re.compile("^\s*(.+)\s+!\s*(.+)\s*::\s*(.+)")

    try:
        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_check= re.search(regex_check, line)
                if match_check:
                    new_check = {'filename': match_check.group(1).strip(), 'name': match_check.group(2).strip(), 'link': match_check.group(3).strip()}
                    data.append(new_check)

    except Exception as e:
        raise WazuhException(1101, str(e))

    return data


def _rootkit_trojans2json(filepath):
    """
    Returns the rootkit trojans file as dictionary.

    :return: rootkit trojans file as dictionary.
    """

    data = []

    # file_name !string_to_search!Description
    regex_comment = re.compile("^\s*#")
    regex_check = re.compile("^\s*(.+)\s+!\s*(.+)\s*!\s*(.+)")

    try:
        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_check= re.search(regex_check, line)
                if match_check:
                    new_check = {'filename': match_check.group(1).strip(), 'name': match_check.group(2).strip(), 'description': match_check.group(3).strip()}
                    data.append(new_check)

    except Exception as e:
        raise WazuhException(1101, str(e))

    return data


# Main functions
def get_ossec_conf(section=None, field=None):
    """
    Returns ossec.conf (manager) as dictionary.

    :param section: Filters by section (i.e. rules).
    :param field: Filters by field in section (i.e. included).
    :return: ossec.conf (manager) as dictionary.
    """

    try:
        # wrap the data
        f = open(common.ossec_conf)
        txt_data = f.read()
        txt_data = txt_data.replace(" -- ", " -INVALID_CHAR ")
        f.close()
        txt_data = '<root_tag>' + txt_data + '</root_tag>'

        # Read XML
        xml_data = fromstring(txt_data)

        # Parse XML to JSON
        data = _ossecconf2json(xml_data)
    except:
        raise WazuhException(1101)

    if section:
        try:
            data = data[section]
        except:
            raise WazuhException(1102)

    if section and field:
        try:
            data = data[field]  # data[section][field]
        except:
            raise WazuhException(1103)

    return data


def get_agent_conf(group_id=None, offset=0, limit=common.database_limit, filename=None):
    """
    Returns agent.conf as dictionary.

    :return: agent.conf as dictionary.
    """

    if group_id:
        if not Agent.group_exists(group_id):
            raise WazuhException(1710, group_id)

        agent_conf = "{0}/{1}".format(common.shared_path, group_id)

    if filename:
        agent_conf_name = filename
    else:
        agent_conf_name = 'agent.conf'

    agent_conf += "/{0}".format(agent_conf_name)

    if not os_path.exists(agent_conf):
        raise WazuhException(1013, agent_conf)

    try:
        # wrap the data
        f = open(agent_conf)
        txt_data = f.read()
        txt_data = txt_data.replace(" -- ", " -INVALID_CHAR ")
        f.close()
        txt_data = '<root_tag>' + txt_data + '</root_tag>'

        # Read XML
        xml_data = fromstring(txt_data)

        # Parse XML to JSON
        data = _agentconf2json(xml_data)
    except:
        raise WazuhException(1101)


    return {'totalItems': len(data), 'items': cut_array(data, offset, limit)}


def get_file_conf(filename, group_id=None, type_conf=None):
    """
    Returns the configuration file as dictionary.

    :return: configuration file as dictionary.
    """

    if group_id:
        if not Agent.group_exists(group_id):
            raise WazuhException(1710, group_id)
        file_path = "{0}/{1}/{2}".format(common.shared_path, group_id, filename)
    else:
        file_path = "{0}/{1}".format(common.shared_path, filename)

    if not os_path.exists(file_path):
        raise WazuhException(1013, file_path)

    types = {
        'conf': get_agent_conf,
        'rootkit_files': _rootkit_files2json,
        'rootkit_trojans': _rootkit_trojans2json,
        'rcl': _rcl2json
    }

    data = {}
    if type_conf:
        if type_conf in types:
            if type_conf == 'conf':
                data = types[type_conf](group_id, limit=0, filename=filename)
            else:
                data = types[type_conf](file_path)
        else:
            raise WazuhException(1104, "{0}. Valid types: {1}".format(type_conf, types.keys()))
    else:
        if filename == "agent.conf":
            data = get_agent_conf(group_id, limit=0, filename=filename)
        elif filename == "rootkit_files.txt":
            data = _rootkit_files2json(file_path)
        elif filename == "rootkit_trojans.txt":
            data = _rootkit_trojans2json(file_path)
        else:
            data = _rcl2json(file_path)

    return data


def get_group_files(group_id=None):

    group_path = common.shared_path
    if group_id:
        if not Agent.group_exists(group_id):
            raise WazuhException(1710, group_id)
        group_path = "{0}/{1}".format(common.shared_path, group_id)

    if not os_path.exists(group_path):
        raise WazuhException(1013, group_path)

    return listdir(group_path)
