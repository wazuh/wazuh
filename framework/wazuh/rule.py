#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from glob import glob
from xml.etree.ElementTree import fromstring
import wazuh.configuration as configuration
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.utils import cut_array, sort_array, search_array, load_wazuh_xml
from sys import version_info

class Rule:
    """
    Rule Object.
    """

    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'
    SORT_FIELDS = ['file', 'path', 'description', 'id', 'level', 'status']

    def __init__(self):
        self.file = None
        self.path = None
        self.description = ""
        self.id = None
        self.level = None
        self.status = None
        self.groups = []
        self.pci = []
        self.gdpr = []
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Rule):
            return self.id < other.id
        else:
            raise WazuhException(1204)

    def __le__(self, other):
        if isinstance(other, Rule):
            return self.id <= other.id
        else:
            raise WazuhException(1204)

    def __gt__(self, other):
        if isinstance(other, Rule):
            return self.id > other.id
        else:
            raise WazuhException(1204)

    def __ge__(self, other):
        if isinstance(other, Rule):
            return self.id >= other.id
        else:
            raise WazuhException(1204)


    def to_dict(self):
        return {'file': self.file, 'path': self.path, 'id': self.id, 'level': self.level, 'description': self.description,
                'status': self.status, 'groups': self.groups, 'pci': self.pci, 'gdpr': self.gdpr, 'details': self.details}


    def set_group(self, group):
        """
        Adds a group to the group list.
        :param group: Group to add (string or list)
        """

        Rule.__add_unique_element(self.groups, group)


    def set_pci(self, pci):
        """
        Adds a pci requirement to the pci list.
        :param pci: Requirement to add (string or list).
        """

        Rule.__add_unique_element(self.pci, pci)


    def set_gdpr(self, gdpr):
        """
        Adds a gdpr requirement to the gdpr list.
        :param gdpr: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.gdpr, gdpr)


    def add_detail(self, detail, value):
        """
        Add a rule detail (i.e. category, noalert, etc.).

        :param detail: Detail name.
        :param value: Detail value.
        """
        if detail in self.details:
            # If it was an element, we create a list.
            if type(self.details[detail]) is not list:
                element = self.details[detail]
                self.details[detail] = [element]

            self.details[detail].append(value)
        else:
            self.details[detail] = value


    @staticmethod
    def __add_unique_element(src_list, element):
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


    @staticmethod
    def __check_status(status):
        if status is None:
            return Rule.S_ALL
        elif status in [Rule.S_ALL, Rule.S_ENABLED, Rule.S_DISABLED]:
            return status
        else:
            raise WazuhException(1202)


    @staticmethod
    def get_rules_files(status=None, path=None, file=None, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of the rule files.

        :param status: Filters by status: enabled, disabled, all.
        :param path: Filters by path.
        :param file: Filters by filename.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        data = []
        status = Rule.__check_status(status)

        # Rules configuration
        ruleset_conf = configuration.get_ossec_conf(section='ruleset')
        if not ruleset_conf:
            raise WazuhException(1200)

        tmp_data = []
        tags = ['rule_include', 'rule_exclude']
        exclude_filenames =[]
        for tag in tags:
            if tag in ruleset_conf:
                item_status = Rule.S_DISABLED if tag == 'rule_exclude' else Rule.S_ENABLED

                if type(ruleset_conf[tag]) is list:
                    items = ruleset_conf[tag]
                else:
                    items = [ruleset_conf[tag]]

                for item in items:
                    if '/' in item:
                        item_split = item.split('/')
                        item_name = item_split[-1]
                        item_dir = "{0}/{1}".format(common.ossec_path, "/".join(item_split[:-1]))
                    else:
                        item_name = item
                        item_dir = "{0}/{1}".format(common.ruleset_rules_path, item)

                    if tag == 'rule_exclude':
                        exclude_filenames.append(item_name)
                        # tmp_data.append({'file': item_name, 'path': '-', 'status': item_status})
                    else:
                        tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

        tag = 'rule_dir'
        if tag in ruleset_conf:
            if type(ruleset_conf[tag]) is list:
                items = ruleset_conf[tag]
            else:
                items = [ruleset_conf[tag]]

            for item_dir in items:
                all_rules = "{0}/{1}/*.xml".format(common.ossec_path, item_dir)

                for item in glob(all_rules):
                    item_split = item.split('/')
                    item_name = item_split[-1]
                    item_dir = "/".join(item_split[:-1])
                    if item_name in exclude_filenames:
                        item_status = Rule.S_DISABLED
                    else:
                        item_status = Rule.S_ENABLED
                    tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

        data = list(tmp_data)
        for d in tmp_data:
            if status and status != 'all' and status != d['status']:
                data.remove(d)
                continue
            if path and path != d['path']:
                data.remove(d)
                continue
            if file and file != d['file']:
                data.remove(d)
                continue

        if search:
            data = search_array(data, search['value'], search['negation'])

        if sort:
            data = sort_array(data, sort['fields'], sort['order'])
        else:
            data = sort_array(data, ['file'], 'asc')

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}


    @staticmethod
    def get_rules(status=None, group=None, pci=None, gdpr=None, path=None, file=None, id=None, level=None, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of rules.

        :param status: Filters by status: enabled, disabled, all.
        :param group: Filters by group.
        :param pci: Filters by pci requirement.
        :param gdpr: Filter by gdpr requirement.
        :param file: Filters by file of the rule.
        :param path: Filters by file of the path.
        :param id: Filters by rule ID.
        :param level: Filters by level. It can be an integer or an range (i.e. '2-4' that means levels from 2 to 4).
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        all_rules = []

        if level:
            levels = level.split('-')
            if len(levels) < 0 or len(levels) > 2:
                raise WazuhException(1203)

        for rule_file in Rule.get_rules_files(status=status, limit=None)['items']:
            all_rules.extend(Rule.__load_rules_from_file(rule_file['file'], rule_file['path'], rule_file['status']))

        rules = list(all_rules)
        for r in all_rules:
            if group and group not in r.groups:
                rules.remove(r)
                continue
            elif pci and pci not in r.pci:
                rules.remove(r)
                continue
            elif gdpr and gdpr not in r.gdpr:
                rules.remove(r)
                continue
            elif path and path != r.path:
                rules.remove(r)
                continue
            elif file and file != r.file:
                rules.remove(r)
                continue
            elif id and int(id) != r.id:
                rules.remove(r)
                continue
            elif level:
                if len(levels) == 1:
                    if int(levels[0]) != r.level:
                        rules.remove(r)
                        continue
                elif not (int(levels[0]) <= r.level <= int(levels[1])):
                        rules.remove(r)
                        continue

        if search:
            rules = search_array(rules, search['value'], search['negation'])

        if sort:
            rules = sort_array(rules, sort['fields'], sort['order'], Rule.SORT_FIELDS)
        else:
            rules = sort_array(rules, ['id'], 'asc')

        return {'items': cut_array(rules, offset, limit), 'totalItems': len(rules)}


    @staticmethod
    def get_groups(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the groups used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        groups = set()

        for rule in Rule.get_rules(limit=None)['items']:
            for group in rule.groups:
                groups.add(group)

        if search:
            groups = search_array(groups, search['value'], search['negation'])

        if sort:
            groups = sort_array(groups, order=sort['order'])
        else:
            groups = sort_array(groups)

        return {'items': cut_array(groups, offset, limit), 'totalItems': len(groups)}


    @staticmethod
    def _get_requirement(offset, limit, sort, search, requirement):
        """
        Get the requirements used in the rules

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param requirement: requirement to get (pci or dgpr)
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        if requirement != 'pci' and requirement != 'gdpr':
            raise WazuhException(1205, requirement)

        req = list({req for rule in Rule.get_rules(limit=None)['items'] for req in rule.to_dict()[requirement]})

        if search:
            req = search_array(req, search['value'], search['negation'])

        if sort:
            req = sort_array(req, order=sort['order'])
        else:
            req = sort_array(req)

        return {'items': cut_array(req, offset, limit), 'totalItems': len(req)}


    @staticmethod
    def get_pci(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the PCI requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement(offset, limit, sort, search, 'pci')


    @staticmethod
    def get_gdpr(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the GDPR requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement(offset, limit, sort, search, 'gdpr')


    @staticmethod
    def __load_rules_from_file(rule_file, rule_path, rule_status):
        try:
            rules = []

            root = load_wazuh_xml("{}/{}".format(rule_path, rule_file))

            for xml_group in root.getchildren():
                if xml_group.tag.lower() == "group":
                    general_groups = xml_group.attrib['name'].split(',')
                    for xml_rule in xml_group.getchildren():
                        # New rule
                        if xml_rule.tag.lower() == "rule":
                            groups = []
                            rule = Rule()
                            rule.file = rule_file
                            rule.path = rule_path
                            rule.id = int(xml_rule.attrib['id'])
                            rule.level = int(xml_rule.attrib['level'])
                            rule.status = rule_status

                            for k in xml_rule.attrib:
                                if k != 'id' and k != 'level':
                                    rule.details[k] = xml_rule.attrib[k]

                            for xml_rule_tags in xml_rule.getchildren():
                                tag = xml_rule_tags.tag.lower()
                                value = xml_rule_tags.text
                                if value == None:
                                    value = ''
                                if tag == "group":
                                    groups.extend(value.split(","))
                                elif tag == "description":
                                    rule.description += value
                                elif tag == "field":
                                    rule.add_detail(xml_rule_tags.attrib['name'], value)
                                elif tag in ("list", "info"):
                                    list_detail = {'name': value}
                                    for attrib, attrib_value in xml_rule_tags.attrib.items():
                                        list_detail[attrib] = attrib_value
                                    rule.add_detail(tag, list_detail)
                                # show rule variables
                                elif tag in {'regex', 'match', 'user', 'id'} and value != '' and value[0] == "$":
                                    for variable in filter(lambda x: x.get('name') == value[1:], root.findall('var')):
                                        rule.add_detail(tag, variable.text)
                                else:
                                    rule.add_detail(tag, value)

                            # Set groups
                            groups.extend(general_groups)

                            pci_groups = []
                            gdpr_groups = []
                            ossec_groups = []
                            for g in groups:
                                if 'pci_dss_' in g:
                                    pci_groups.append(g.strip()[8:])
                                elif 'gdpr_' in g:
                                    gdpr_groups.append(g.strip()[5:])
                                else:
                                    ossec_groups.append(g)

                            rule.set_group(ossec_groups)
                            rule.set_pci(pci_groups)
                            rule.set_gdpr(gdpr_groups)

                            rules.append(rule)
        except Exception as e:
            raise WazuhException(1201, "{0}. Error: {1}".format(rule_file, str(e)))

        return rules
