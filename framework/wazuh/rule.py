# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import wazuh.core.configuration as configuration
from wazuh.core import common
from wazuh.core.rule import check_status, load_rules_from_file, format_rule_decoder_file, REQUIRED_FIELDS, \
    RULE_REQUIREMENTS, SORT_FIELDS
from wazuh.core.exception import WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array


def get_rules(rule_ids=None, status=None, group=None, pci_dss=None, gpg13=None, gdpr=None, hipaa=None, nist_800_53=None,
              tsc=None, mitre=None, relative_dirname=None, filename=None, level=None, offset=0,
              limit=common.database_limit, select=None, sort_by=None, sort_ascending=True, search_text=None,
              complementary_search=False, search_in_fields=None, q=''):
    """Gets a list of rules.

    :param rule_ids: IDs of rules.
    :param status: Filters the rules by status.
    :param group: Filters the rules by group.
    :param pci_dss: Filters the rules by pci_dss requirement.
    :param gpg13: Filters the rules by gpg13 requirement.
    :param gdpr: Filters the rules by gdpr requirement.
    :param hipaa: Filters the rules by hipaa requirement.
    :param nist_800_53: Filters the rules by nist_800_53 requirement.
    :param tsc: Filters the rules by tsc requirement.
    :param mitre: Filters the rules by mitre attack ID.
    :param relative_dirname: Filters the relative dirname.
    :param filename: List of filenames to filter by.
    :param level: Filters the rules by level. level=2 or level=2-5.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param select: List of selected fields to return
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param q: Defines query to filter.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No rule was returned',
                                      some_msg='Some rules were not returned',
                                      all_msg='All selected rules were returned')
    rules = list()
    if rule_ids is None:
        rule_ids = list()
    levels = None

    if level:
        levels = level.split('-')
        if len(levels) < 0 or len(levels) > 2:
            raise WazuhError(1203)

    for rule_file in get_rules_files(limit=None).affected_items:
        rules.extend(load_rules_from_file(rule_file['filename'], rule_file['relative_dirname'], rule_file['status']))

    status = check_status(status)
    status = ['enabled', 'disabled'] if status == 'all' else [status]
    parameters = {'groups': group, 'pci_dss': pci_dss, 'gpg13': gpg13, 'gdpr': gdpr, 'hipaa': hipaa,
                  'nist_800_53': nist_800_53, 'tsc': tsc, 'mitre': mitre, 'relative_dirname': relative_dirname,
                  'filename': filename, 'id': rule_ids, 'level': levels, 'status': status}
    original_rules = list(rules)
    no_existent_ids = rule_ids[:]
    for r in original_rules:
        if r['id'] in no_existent_ids:
            no_existent_ids.remove(r['id'])
        for key, value in parameters.items():
            if value:
                if key == 'level' and (len(value) == 1 and int(value[0]) != r['level'] or len(value) == 2
                                       and not int(value[0]) <= r['level'] <= int(value[1])) or \
                        (key == 'id' and r[key] not in value) or \
                        (key == 'filename' and r[key] not in filename) or \
                        (key == 'status' and r[key] not in value) or \
                        (not isinstance(value, list) and value not in r[key]):
                    rules.remove(r)
                    break

    for rule_id in no_existent_ids:
        result.add_failed_item(id_=rule_id, error=WazuhError(1208))

    data = process_array(rules, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, select=select, sort_by=sort_by,
                         sort_ascending=sort_ascending, allowed_sort_fields=SORT_FIELDS, offset=offset,
                         limit=limit, q=q, required_fields=REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['rules:read'], resources=['rule:file:{filename}'])
def get_rules_files(status=None, relative_dirname=None, filename=None, offset=0, limit=common.database_limit, sort_by=None,
                    sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Gets a list of the rule files.

    :param status: Filters by status: enabled, disabled, all.
    :param relative_dirname: Filters by relative dirname.
    :param filename: List of filenames to filter by.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(none_msg='No rule files were returned',
                                      some_msg='Some rule files were not returned',
                                      all_msg='All rule files were returned')
    status = check_status(status)
    # Rules configuration
    ruleset_conf = configuration.get_ossec_conf(section='ruleset')
    if not ruleset_conf:
        raise WazuhError(1200)
    rules_files = list()
    tags = ['rule_include', 'rule_exclude', 'rule_dir']
    if isinstance(filename, list):
        for f in filename:
            rules_files.extend(
                format_rule_decoder_file(ruleset_conf['ruleset'],
                                         {'status': status, 'relative_dirname': relative_dirname, 'filename': f},
                                         tags))
    else:
        rules_files = format_rule_decoder_file(ruleset_conf['ruleset'],
                                               {'status': status, 'relative_dirname': relative_dirname, 'filename': filename},
                                               tags)

    data = process_array(rules_files, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


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
    result = AffectedItemsWazuhResult(none_msg='No groups in rules were returned',
                                      some_msg='Some groups in rules were not returned',
                                      all_msg='All groups in rules were returned')

    groups = {group for rule in get_rules(limit=None).affected_items for group in rule['groups']}

    data = process_array(list(groups), search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


def get_requirement(requirement=None, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True,
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
    result = AffectedItemsWazuhResult(none_msg='No rule was returned',
                                      all_msg='All selected rules were returned')

    if requirement not in RULE_REQUIREMENTS:
        result.add_failed_item(id_=requirement, error=WazuhError(1205, extra_message=requirement,
                               extra_remediation=f'Valid ones are {RULE_REQUIREMENTS}'))

        return result

    req = list({req for rule in get_rules(limit=None).affected_items for req in rule[requirement]})

    data = process_array(req, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


def get_file(filename=None):
    """Reads content of specified file

    :param filename: File name to read content from
    :return: File contents
    """
    files = get_rules_files(filename=filename).affected_items

    if len(files) > 0:
        rules_path = files[0]['relative_dirname']
        try:
            full_path = os.path.join(common.ossec_path, rules_path, filename)
            with open(full_path) as f:
                return f.read()
        except OSError:
            raise WazuhError(1414, extra_message=os.path.join('WAZUH_HOME', rules_path, filename))
    else:
        raise WazuhError(1415)
