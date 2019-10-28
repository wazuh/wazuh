# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from enum import Enum
from glob import glob

from wazuh import common
from wazuh.exception import WazuhError
from wazuh.utils import load_wazuh_xml


class Status(Enum):
    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'
    SORT_FIELDS = ['file', 'path', 'description', 'id', 'level', 'status']


def add_detail(detail, value, details):
    """Add a rule detail (i.e. category, noalert, etc.).

    :param detail: Detail name.
    :param value: Detail value.
    :param details: Details dict.
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
    new_list = list()
    new_list.extend(element) if type(element) in [list, tuple] else new_list.append(element)

    for item in new_list:
        if item is not None and item != '':
            i = item.strip()
            if i not in src_list:
                src_list.append(i)


def check_status(status):
    if status is None:
        return Status.S_ALL.value
    elif status in Status.SORT_FIELDS.value:
        return status
    else:
        raise WazuhError(1202)


def set_groups(groups, general_groups, rule):
    pci_groups, gpg13_groups, gdpr_groups, hipaa_groups, nist_800_53_groups, ossec_groups = (list() for i in range(6))
    guidelines = {'pci_dss_': 8, 'gpg13_': 6, 'gdpr_': 5, 'hipaa_': 6, 'nist_800_53_':12}
    groups.extend(general_groups)
    for g in groups:
        for key, value in guidelines:
            pci_groups.append(g.strip()[value:]) if key in g else ossec_groups.append(g)

    add_unique_element(rule['pci'], pci_groups)
    add_unique_element(rule['gpg13'], gpg13_groups)
    add_unique_element(rule['gdpr'], gdpr_groups)
    add_unique_element(rule['hipaa'], hipaa_groups)
    add_unique_element(rule['nist_800_53'], nist_800_53_groups)
    add_unique_element(rule['groups'], ossec_groups)


def load_rules_from_file(rule_file, rule_path, rule_status):
    try:
        rules = list()
        root = load_wazuh_xml(os.path.join(common.ossec_path, rule_path, rule_file))

        for xml_group in list(root):
            if xml_group.tag.lower() == "group":
                general_groups = xml_group.attrib['name'].split(',')
                for xml_rule in list(xml_group):
                    # New rule
                    if xml_rule.tag.lower() == "rule":
                        groups = list()
                        rule = {'file': rule_file, 'path': rule_path, 'id': int(xml_rule.attrib['id']),
                                'level': int(xml_rule.attrib['level']), 'status': rule_status, 'details': dict(),
                                'pci': list(), 'gpg13': list(), 'gdpr': list(), 'hipaa': list(), 'nist_800_53': list(),
                                'groups': list(), 'description': ''}
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
                                add_detail(xml_rule_tags.attrib['name'], value, rule['details'])
                            elif tag in ("list", "info"):
                                list_detail = {'name': value}
                                for attrib, attrib_value in xml_rule_tags.attrib.items():
                                    list_detail[attrib] = attrib_value
                                add_detail(tag, list_detail, rule['details'])
                            # show rule variables
                            elif tag in {'regex', 'match', 'user', 'id'} and value != '' and value[0] == "$":
                                for variable in filter(lambda x: x.get('name') == value[1:], root.findall('var')):
                                    add_detail(tag, variable.text, rule['details'])
                            else:
                                add_detail(tag, value, rule['details'])

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


def process_rule(rules, parameters):
    original_rules = list(rules)
    for r in original_rules:
        for key, value in parameters.items():
            if key == 'level' and value:
                if len(value) == 1:
                    if int(value[0]) != r['level']:
                        rules.remove(r)
                elif not (int(value[0]) <= r['level'] <= int(value[1])):
                    rules.remove(r)
            if value and value not in r[key]:
                rules.remove(r)


def format_rule_file(ruleset_conf, parameters):
    tmp_data, exclude_filenames = (list() for i in range(2))
    tags = ['rule_include', 'rule_exclude']
    for tag in tags:
        if tag in ruleset_conf:
            item_status = Status.S_DISABLED.value if tag == 'rule_exclude' else Status.S_ENABLED.value
            items = ruleset_conf[tag] if type(ruleset_conf[tag]) is list else [ruleset_conf[tag]]
            for item in items:
                item_name = os.path.basename(item)
                full_dir = os.path.dirname(item)
                item_dir = os.path.relpath(full_dir if full_dir else common.ruleset_rules_path,
                                           start=common.ossec_path)
                exclude_filenames.append(item_name) if tag == 'rule_exclude' else \
                    tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

    tag = 'rule_dir'
    if tag in ruleset_conf:
        items = ruleset_conf[tag] if type(ruleset_conf[tag]) is list else [ruleset_conf[tag]]
        for item_dir in items:
            all_rules = f"{common.ossec_path}/{item_dir}/*.xml"
            for item in glob(all_rules):
                item_name = os.path.basename(item)
                item_dir = os.path.relpath(os.path.dirname(item), start=common.ossec_path)
                item_status = Status.S_DISABLED.value if item_name in exclude_filenames else Status.S_ENABLED.value
                tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

    data = list(tmp_data)
    for d in tmp_data:
        for key, value in parameters.items():
            if key == 'status':
                if value and value != Status.S_ALL.value and value != d[key]:
                    data.remove(d)
            elif value and value != d[key]:
                data.remove(d)

    return data
