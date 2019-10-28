# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import wazuh.configuration as configuration
from wazuh import common
from wazuh.core.rule import check_status, load_rules_from_file, Status, process_rule, format_rule_file
from wazuh.exception import WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.results import AffectedItemsWazuhResult
from wazuh.utils import process_array


@expose_resources(actions='rules:read', resources=['*:*:*'])
def get_rules(rule_ids=None, status=None, group=None, pci=None, gpg13=None, gdpr=None, hipaa=None, nist_800_53=None,
              path=None, file=None, level=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None, q=''):
    """Gets a list of rules.

    :param rule_ids: IDs of rules.
    :param status: Filters the rules by status.
    :param group: Filters the rules by group.
    :param pci: Filters the rules by pci requirement.
    :param gpg13: Filters the rules by gpg13 requirement.
    :param gdpr: Filters the rules by gdpr requirement.
    :param hipaa: Filters the rules by hipaa requirement.
    :param nist_800_53: Filters the rules by nist_800_53 requirement.
    :param path: Filters the rules by path.
    :param file: Filters the rules by file name.
    :param level: Filters the rules by level. level=2 or level=2-5.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param q: Defines query to filter.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No rule was shown',
                                      some_msg='Some rules could not be shown',
                                      all_msg='All selected rules were shown')
    rules = []
    levels = None

    if level:
        levels = level.split('-')
        if len(levels) < 0 or len(levels) > 2:
            raise WazuhError(1203)

    for rule_file in get_rules_files(status=status, limit=None).affected_items:
        rules.extend(load_rules_from_file(rule_file['file'], rule_file['path'], rule_file['status']))

    parameters = {'groups': group, 'pci': pci, 'gpg13': gpg13, 'gdpr': gdpr, 'hipaa': hipaa, 'nist_800_53': nist_800_53,
                  'path': path, 'file': file, 'id': rule_ids, 'level': levels}

    process_rule(rules, parameters)
    result.affected_items = process_array(rules, search_text=search_text, search_in_fields=search_in_fields,
                                          complementary_search=complementary_search, sort_by=sort_by,
                                          sort_ascending=sort_ascending, allowed_sort_fields=Status.SORT_FIELDS.value,
                                          offset=offset, limit=limit, q=q)['items']
    result.total_affected_items = len(rules)

    return result


@expose_resources(actions='rules:read', resources=['*:*:*'])
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
    result = AffectedItemsWazuhResult(none_msg='No rules files were shown',
                                      some_msg='Some rules files were shown',
                                      all_msg='All rules files were shown')
    status = check_status(status)
    # Rules configuration
    ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
    if not ruleset_conf:
        raise WazuhError(1200)

    result.affected_items = process_array(
        format_rule_file(ruleset_conf, {'status': status, 'path': path, 'file': file}),
        search_text=search_text, search_in_fields=search_in_fields, complementary_search=complementary_search,
        sort_by=sort_by, sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions='rules:read', resources=['*:*:*'])
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
    result = AffectedItemsWazuhResult(none_msg='No groups in rules are shown',
                                      some_msg='Some groups in rules are shown',
                                      all_msg='All groups in rules are shown')
    groups = set()
    for rule in get_rules(limit=None).affected_items:
        for group in rule['groups']:
            groups.add(group)

    result.affected_items = process_array(list(groups), search_text=search_text, search_in_fields=search_in_fields,
                                          complementary_search=complementary_search, sort_by=sort_by,
                                          sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions='rules:read', resources=['*:*:*'])
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
    result = AffectedItemsWazuhResult(none_msg='No rule was shown',
                                      all_msg='Selected rules were shown')
    valid_requirements = ['pci', 'gdpr', 'hipaa', 'nist-800-53', 'gpg13']

    if requirement not in valid_requirements:
        result.add_failed_item(id_=requirement,
                               error=WazuhError(1205, extra_message=requirement, extra_remediation=valid_requirements))

    req = list({req for rule in get_rules(limit=None).affected_items for req in rule[requirement]})

    result.affected_items = process_array(req, search_text=search_text, search_in_fields=search_in_fields,
                                          complementary_search=complementary_search, sort_by=sort_by,
                                          sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions='rules:read', resources=['*:*:*'])
def get_file(filename=None):
    """Reads content of specified file

    :param filename: File name to read content from
    :return: File contents
    """
    files = get_rules_files(file=filename).affected_items

    if len(files) > 0:
        rules_path = files[0]['path']
        try:
            full_path = os.path.join(common.ossec_path, rules_path, filename)
            with open(full_path) as f:
                return f.read()
        except OSError:
            raise WazuhError(1414, extra_message=os.path.join('WAZUH_HOME', rules_path, filename))
        except Exception:
            raise WazuhError(1413, extra_message=os.path.join('WAZUH_HOME', rules_path, filename))
    else:
        raise WazuhError(1415)
