# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from enum import Enum
from wazuh import common
from wazuh.utils import load_wazuh_xml
from wazuh.exception import WazuhError


class Status(Enum):
    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'
    SORT_FIELDS = ['file', 'path', 'description', 'id', 'level', 'status']


def add_detail(detail, value, details):
    """Add a rule detail (i.e. category, noalert, etc.).

    :param detail: Detail name.
    :param value: Detail value.
    """
    if detail in details:
        # If it was an element, we create a list.
        if type(details[detail]) is not list:
            element = details[detail]
            details[detail] = [element]

        details[detail].append(value)
    else:
        details[detail] = value


def add_unique_element(src_list, element):
    new_list = []

    if type(element) in [list, tuple]:
        new_list.extend(element)
    else:
        new_list.append(element)

    for item in new_list:
        if item is not None and item != '':
            i = item.strip()
            if i not in src_list:
                src_list.append(i)


def check_status(status):
    if status is None:
        return Status.S_ALL
    elif status in Status.SORT_FIELDS:
        return status
    else:
        raise WazuhError(1202)


def set_groups(groups, general_groups, rule):
    groups.extend(general_groups)

    pci_groups = []
    gpg13_groups = []
    gdpr_groups = []
    hipaa_groups = []
    nist_800_53_groups = []
    ossec_groups = []
    for g in groups:
        if 'pci_dss_' in g:
            pci_groups.append(g.strip()[8:])
        elif 'gpg13_' in g:
            gpg13_groups.append(g.strip()[6:])
        elif 'gdpr_' in g:
            gdpr_groups.append(g.strip()[5:])
        elif 'hipaa_' in g:
            hipaa_groups.append(g.strip()[6:])
        elif 'nist_800_53_' in g:
            nist_800_53_groups.append(g.strip()[12:])
        else:
            ossec_groups.append(g)

    _add_unique_element(rule['pci'], pci_groups)
    _add_unique_element(rule['gpg13'], gpg13_groups)
    _add_unique_element(rule['gdpr'], gdpr_groups)
    _add_unique_element(rule['hipaa'], hipaa_groups)
    _add_unique_element(rule['nist_800_53'], nist_800_53_groups)
    _add_unique_element(rule['groups'], ossec_groups)


def load_rules_from_file(rule_file, rule_path, rule_status):
    try:
        rules = []
        root = load_wazuh_xml(os.path.join(common.ossec_path, rule_path, rule_file))

        for xml_group in list(root):
            if xml_group.tag.lower() == "group":
                general_groups = xml_group.attrib['name'].split(',')
                for xml_rule in list(xml_group):
                    # New rule
                    if xml_rule.tag.lower() == "rule":
                        groups = []
                        rule = {'file': rule_file, 'path': rule_path, 'id': int(xml_rule.attrib['id']),
                                'level': int(xml_rule.attrib['level']), 'status': rule_status, 'details': dict(),
                                'pci': list(), 'gpg13': list(), 'gdpr': list(), 'hipaa': list(), 'nist_800_53': list(),
                                'groups': list()}
                        for k in xml_rule.attrib:
                            if k != 'id' and k != 'level':
                                rule['details'][k] = xml_rule.attrib[k]

                        for xml_rule_tags in list(xml_rule):
                            tag = xml_rule_tags.tag.lower()
                            value = xml_rule_tags.text
                            if value is None:
                                value = ''
                            if tag == "group":
                                groups.extend(value.split(","))
                            elif tag == "description":
                                rule['description'] += value
                            elif tag == "field":
                                _add_detail(xml_rule_tags.attrib['name'], value, rule['details'])
                            elif tag in ("list", "info"):
                                list_detail = {'name': value}
                                for attrib, attrib_value in xml_rule_tags.attrib.items():
                                    list_detail[attrib] = attrib_value
                                _add_detail(tag, list_detail, rule['details'])
                            # show rule variables
                            elif tag in {'regex', 'match', 'user', 'id'} and value != '' and value[0] == "$":
                                for variable in filter(lambda x: x.get('name') == value[1:], root.findall('var')):
                                    _add_detail(tag, variable.text, rule['details'])
                            else:
                                _add_detail(tag, value, rule['details'])

                        # Set groups
                        set_groups(groups=groups, general_groups=general_groups, rule=rule)
                        rules.append(rule)
    except OSError as e:
        if e.errno == 2:
            raise WazuhError(1201)
        elif e.errno == 13:
            raise WazuhError(1207)
        else:
            raise e

    return rules
