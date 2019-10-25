# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from glob import glob

import wazuh.configuration as configuration
from wazuh import common
from wazuh.exception import WazuhInternalError, WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.results import AffectedItemsWazuhResult
from wazuh.utils import process_array
from wazuh.core.crule import check_status, load_rules_from_file, Status


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
    all_rules = []
    levels = None

    if level:
        levels = level.split('-')
        if len(levels) < 0 or len(levels) > 2:
            raise WazuhError(1203)

    for rule_file in get_rules_files(status=status, limit=None):
        all_rules.extend(load_rules_from_file(rule_file['file'], rule_file['path'], rule_file['status']))

    import pydevd_pycharm
    pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    rules = list(all_rules)
    for r in all_rules:
        if group and group not in r['groups']:
            rules.remove(r)
        elif pci and pci not in r['pci']:
            rules.remove(r)
        elif gpg13 and gpg13 not in r['gpg13']:
            rules.remove(r)
        elif gdpr and gdpr not in r['gdpr']:
            rules.remove(r)
        elif hipaa and hipaa not in r['hipaa']:
            rules.remove(r)
        elif nist_800_53 and nist_800_53 not in r['nist_800_53']:
            rules.remove(r)
        elif path and path != r['path']:
            rules.remove(r)
        elif file and file != r['file']:
            rules.remove(r)
        elif rule_ids and r['id'] not in rule_ids:
            rules.remove(r)
        elif level:
            if len(levels) == 1:
                if int(levels[0]) != r['level']:
                    rules.remove(r)
            elif not (int(levels[0]) <= r['level'] <= int(levels[1])):
                rules.remove(r)

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
    status = check_status(status)

    # Rules configuration
    ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
    if not ruleset_conf:
        raise WazuhError(1200)

    tmp_data = []
    tags = ['rule_include', 'rule_exclude']
    exclude_filenames = []
    for tag in tags:
        if tag in ruleset_conf:
            item_status = Status.S_DISABLED.value if tag == 'rule_exclude' else Status.S_ENABLED.value

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
                    item_status = Status.S_DISABLED.value
                else:
                    item_status = Status.S_ENABLED.value
                tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

    data = list(tmp_data)
    for d in tmp_data:
        if status and status != Status.S_ALL.value and status != d['status']:
            data.remove(d)
        if path and path != d['path']:
            data.remove(d)
        if file and file != d['file']:
            data.remove(d)

    return process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)['items']


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

    for rule in get_rules(limit=None)['items']:
        for group in rule.groups:
            groups.add(group)

    result.affected_items.append(process_array(groups, search_text=search_text, search_in_fields=search_in_fields,
                                               complementary_search=complementary_search, sort_by=sort_by,
                                               sort_ascending=sort_ascending, offset=offset, limit=limit)['items'])

    return result


@expose_resources(actions='rules:read', resources=['*:*:*'])
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

    req = list({req for rule in get_rules(limit=None)['items'] for req in rule.to_dict()[requirement]})

    return process_array(req, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)['items']


@expose_resources(actions='rules:read', resources=['*:*:*'])
def get_file(filename=None):
    """Reads content of specified file

    :param filename: File name to read content from
    :return: File contents
    """
    data = get_rules_files(file=filename)
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
