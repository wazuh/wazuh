# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from glob import glob

import wazuh.configuration as configuration
from wazuh import common
from wazuh.exception import WazuhInternalError, WazuhError
from wazuh.utils import load_wazuh_xml, process_array


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
        self.gpg13 = []
        self.gdpr = []
        self.hipaa = []
        self.nist_800_53 = []
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Rule):
            return self.id < other.id
        else:
            raise WazuhInternalError(1204)

    def __le__(self, other):
        if isinstance(other, Rule):
            return self.id <= other.id
        else:
            raise WazuhInternalError(1204)

    def __gt__(self, other):
        if isinstance(other, Rule):
            return self.id > other.id
        else:
            raise WazuhInternalError(1204)

    def __ge__(self, other):
        if isinstance(other, Rule):
            return self.id >= other.id
        else:
            raise WazuhInternalError(1204)

    def to_dict(self):
        return {'file': self.file, 'path': self.path, 'id': self.id, 'description': self.description,
                'level': self.level, 'status': self.status, 'groups': self.groups, 'pci': self.pci, 'gdpr': self.gdpr,
                'hipaa': self.hipaa, 'nist-800-53': self.nist_800_53, 'gpg13': self.gpg13, 'details': self.details}

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

    def set_gpg13(self, gpg13):
        """
        Adds a gpg13 requirement to the gpg13 list.
        :param gpg13: Requirement to add (string or list).
        """

        Rule.__add_unique_element(self.gpg13, gpg13)

    def set_gdpr(self, gdpr):
        """
        Adds a gdpr requirement to the gdpr list.
        :param gdpr: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.gdpr, gdpr)

    def set_hipaa(self, hipaa):
        """
        Adds a hipaa requirement to the hipaa list.
        :param hipaa: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.hipaa, hipaa)

    def set_nist_800_53(self, nist_800_53):
        """
        Adds a nist_800_53 requirement to the nist_800_53 list.
        :param nist_800_53: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.nist_800_53, nist_800_53)

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
            raise WazuhError(1202)

    @staticmethod
    def get_rules_files(status=None, path=None, file=None, offset=0, limit=common.database_limit, sort_by=None,
                        sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
        """Gets a list of the rule files.

        :param status: Filters by status: enabled, disabled, all.
        :param path: Filters by path.
        :param file: Filters by filename.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort_by: Fields to sort the items by
        :param sort_ascending: Sort in ascending (true) or descending (false) order
        :param search_text: Text to search
        :param complementary_search: Find items without the text to search
        :param search_in_fields: Fields to search in
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        status = Rule.__check_status(status)

        # Rules configuration
        ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
        if not ruleset_conf:
            raise WazuhError(1200)

        tmp_data = []
        tags = ['rule_include', 'rule_exclude']
        exclude_filenames = []
        for tag in tags:
            if tag in ruleset_conf:
                item_status = Rule.S_DISABLED if tag == 'rule_exclude' else Rule.S_ENABLED

                if type(ruleset_conf[tag]) is list:
                    items = ruleset_conf[tag]
                else:
                    items = [ruleset_conf[tag]]

                for item in items:
                    item_name = os.path.basename(item)
                    full_dir = os.path.dirname(item)
                    item_dir = os.path.relpath(full_dir if full_dir else common.ruleset_rules_path,
                                               start=common.ossec_path)
                    if tag == 'rule_exclude':
                        exclude_filenames.append(item_name)
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
                    item_name = os.path.basename(item)
                    item_dir = os.path.relpath(os.path.dirname(item), start=common.ossec_path)
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

        return process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                             complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                             offset=offset, limit=limit)

    @staticmethod
    def get_rules(status=None, group=None, pci=None, gpg13=None, gdpr=None, hipaa=None, nist_800_53=None, path=None,
                  file=None, id=None, level=None, offset=0, limit=common.database_limit, sort_by=None,
                  sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
        """Gets a list of rules.

        :param status: Filters by status: enabled, disabled, all.
        :param group: Filters by group.
        :param pci: Filters by pci requirement.
        :param gpg13: Filter by gpg13 requirement.
        :param gdpr: Filter by gdpr requirement.
        :param hipaa: Filter by hipaa requirement.
        :param nist_800_53: Filter by nist_800_53 requirement.
        :param file: Filters by file of the rule.
        :param path: Filters by file of the path.
        :param id: Filters by rule ID.
        :param level: Filters by level. It can be an integer or an range (i.e. '2-4' that means levels from 2 to 4).
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort_by: Fields to sort the items by
        :param sort_ascending: Sort in ascending (true) or descending (false) order
        :param search_text: Text to search
        :param complementary_search: Find items without the text to search
        :param search_in_fields: Fields to search in
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        all_rules = []

        if level:
            levels = level.split('-')
            if len(levels) < 0 or len(levels) > 2:
                raise WazuhError(1203)

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
            elif gpg13 and gpg13 not in r.gpg13:
                rules.remove(r)
                continue
            elif gdpr and gdpr not in r.gdpr:
                rules.remove(r)
                continue
            elif hipaa and hipaa not in r.hipaa:
                rules.remove(r)
                continue
            elif nist_800_53 and nist_800_53 not in r.nist_800_53:
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

        return process_array(rules, search_text=search_text, search_in_fields=search_in_fields,
                             complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                             allowed_sort_fields=Rule.SORT_FIELDS, offset=offset, limit=limit)

    @staticmethod
    def get_groups(offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True, search_text=None,
                   complementary_search=False, search_in_fields=None):
        """Get all the groups used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort_by: Fields to sort the items by
        :param sort_ascending: Sort in ascending (true) or descending (false) order
        :param search_text: Text to search
        :param complementary_search: Find items without the text to search
        :param search_in_fields: Fields to search in
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        groups = set()

        for rule in Rule.get_rules(limit=None)['items']:
            for group in rule.groups:
                groups.add(group)

        return process_array(groups, search_text=search_text, search_in_fields=search_in_fields,
                             complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                             offset=offset, limit=limit)

    @staticmethod
    def get_requirement(requirement, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True,
                        search_text=None, complementary_search=False, search_in_fields=None):
        """Get the requirements used in the rules

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort_by: Fields to sort the items by
        :param sort_ascending: Sort in ascending (true) or descending (false) order
        :param search_text: Text to search
        :param complementary_search: Find items without the text to search
        :param search_in_fields: Fields to search in
        :param requirement: Requirement to get
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        valid_requirements = ['pci', 'gdpr', 'hipaa', 'nist-800-53', 'gpg13']

        if requirement not in valid_requirements:
            raise WazuhError(1205, extra_message=requirement, extra_remediation=valid_requirements)

        req = list({req for rule in Rule.get_rules(limit=None)['items'] for req in rule.to_dict()[requirement]})

        return process_array(req, search_text=search_text, search_in_fields=search_in_fields,
                             complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                             offset=offset, limit=limit)

    @staticmethod
    def __load_rules_from_file(rule_file, rule_path, rule_status):
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
                            rule = Rule()
                            rule.file = rule_file
                            rule.path = rule_path
                            rule.id = int(xml_rule.attrib['id'])
                            rule.level = int(xml_rule.attrib['level'])
                            rule.status = rule_status

                            for k in xml_rule.attrib:
                                if k != 'id' and k != 'level':
                                    rule.details[k] = xml_rule.attrib[k]

                            for xml_rule_tags in list(xml_rule):
                                tag = xml_rule_tags.tag.lower()
                                value = xml_rule_tags.text
                                if value is None:
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
                            gpg13_groups = []
                            gdpr_groups = []
                            hippa_groups = []
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
                                    hippa_groups.append(g.strip()[6:])
                                elif 'nist_800_53_' in g:
                                    nist_800_53_groups.append(g.strip()[12:])
                                else:
                                    ossec_groups.append(g)

                            rule.set_pci(pci_groups)
                            rule.set_gpg13(gpg13_groups)
                            rule.set_gdpr(gdpr_groups)
                            rule.set_hipaa(hippa_groups)
                            rule.set_nist_800_53(nist_800_53_groups)
                            rule.set_group(ossec_groups)

                            rules.append(rule)
        except OSError as e:
            if e.errno == 2:
                raise WazuhError(1201)
            elif e.errno == 13:
                raise WazuhError(1207)
            else:
                raise e

        return rules

    @staticmethod
    def get_file(filename=None):
        """Reads content of specified file

        :param filename: File name to read content from
        :return: File contents
        """
        data = Rule.get_rules_files(file=filename)
        files = data['items']

        if len(files) > 0:
            rules_path = files[0]['path']
            try:
                full_path = os.path.join(common.ossec_path, rules_path, filename)
                with open(full_path) as f:
                    file_content = f.read()
                return file_content
            except OSError:
                raise WazuhError(1414, extra_message=os.path.join('WAZUH_HOME', rules_path, filename))
            except Exception:
                raise WazuhInternalError(1413, extra_message=os.path.join('WAZUH_HOME', rules_path, filename))
        else:
            raise WazuhError(1415)
