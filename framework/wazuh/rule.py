# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import remove
from os.path import exists, join, normpath, commonpath
from typing import Union, Tuple
from xml.parsers.expat import ExpatError

import xmltodict

import wazuh.core.configuration as configuration
from wazuh.core import common
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.rule import check_status, load_rules_from_file, format_rule_decoder_file, REQUIRED_FIELDS, \
    RULE_REQUIREMENTS, SORT_FIELDS, RULE_FIELDS, RULE_FILES_FIELDS, RULE_FILES_REQUIRED_FIELDS
from wazuh.core.utils import process_array, safe_move, \
    validate_wazuh_xml, upload_file, full_copy, to_relative_path
from wazuh.core.logtest import validate_dummy_logtest
from wazuh.rbac.decorators import expose_resources

cluster_enabled = not read_cluster_config(from_import=True)['disabled']
node_id = get_node().get('node') if cluster_enabled else 'manager'


def get_rules(rule_ids: list = None, status: str = None, group: str = None, pci_dss: str = None, gpg13: str = None,
              gdpr: str = None, hipaa: str = None, nist_800_53: str = None, tsc: str = None, mitre: str = None,
              relative_dirname: str = None, filename: list = None, level: str = None, offset: int = 0,
              limit: int = common.DATABASE_LIMIT, select: str = None, sort_by: dict = None, sort_ascending: bool = True,
              search_text: str = None, complementary_search: bool = False, search_in_fields: list = None,
              q: str = '', distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get a list of rules.

    Parameters
    ----------
    rule_ids : list
        Filters by rule ID.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    select : str
        Select which fields to return (separated by comma).
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    status : str
        Filters by rules status.
    group : str
        Filters by rule group.
    level : str
        Filters by rule level. Can be a single level (4) or an interval (2-4).
    filename : list
        List of filenames to filter by.
    relative_dirname : str
        Filters by relative dirname.
    pci_dss : str
        Filters by PCI_DSS requirement name.
    gdpr : str
        Filters by GDPR requirement.
    gpg13 : str
        Filters by GPG13 requirement.
    nist_800_53 : str
        Filters the rules by nist_800_53 requirement.
    hipaa : str
        Filters by HIPAA requirement.
    tsc : str
        Filters by TSC requirement.
    mitre : str
        Filters by mitre technique ID.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    search_in_fields : list
        Fields to search in.
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhError(1203)
        Error in argument 'level'.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
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
                         limit=limit, q=q, required_fields=REQUIRED_FIELDS, allowed_select_fields=RULE_FIELDS,
                         distinct=distinct)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['rules:read'], resources=['rule:file:{filename}'])
def get_rules_files(status: str = None, relative_dirname: str = None, filename: list = None, offset: int = 0,
                    limit: int = common.DATABASE_LIMIT, sort_by: dict = None, sort_ascending: bool = True,
                    search_text: str = None, complementary_search: bool = False,
                    search_in_fields: list = None, q: str = None, select: str = None,
                    distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get a list of the rule files.

    Parameters
    ----------
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    status : str
        Filters by rules status.
    filename : list
        List of filenames to filter by.
    relative_dirname : str
        Filters by relative dirname.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    search_in_fields : list
        Fields to search in.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhError(1200)
        Error reading rules from `WAZUH_HOME/etc/ossec.conf`.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
                                               {'status': status, 'relative_dirname': relative_dirname,
                                                'filename': filename},
                                               tags)

    data = process_array(rules_files, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, q=q, select=select, allowed_select_fields=RULE_FILES_FIELDS,
                         distinct=distinct, required_fields=RULE_FILES_REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


def get_groups(offset: int = 0, limit: int = common.DATABASE_LIMIT, sort_by: dict = None, sort_ascending: bool = True,
               search_text: str = None, complementary_search: bool = False,
               search_in_fields: list = None) -> AffectedItemsWazuhResult:
    """Get all the groups used in the rules.

    Parameters
    ----------
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    search_in_fields : list
        Fields to search in.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
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


def get_requirement(requirement: str = None, offset: int = 0, limit: int = common.DATABASE_LIMIT, sort_by: dict = None,
                    sort_ascending: bool = True, search_text: str = None, complementary_search: bool = False,
                    search_in_fields: list = None) -> AffectedItemsWazuhResult:
    """Get the requirements used in the rules

    Parameters
    ----------
    requirement : str
        Requirement to get.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    search_in_fields : list
        Fields to search in.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No rule was returned',
                                      all_msg='All selected rules were returned')

    if requirement not in RULE_REQUIREMENTS:
        result.add_failed_item(id_=requirement,
                               error=WazuhError(1205, extra_message=requirement,
                                                extra_remediation=f'Valid ones are {RULE_REQUIREMENTS}'))

        return result

    req = list({req for rule in get_rules(limit=None).affected_items for req in rule[requirement]})

    data = process_array(req, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result

def get_rule_file_path(filename: str = None, relative_dirname: str = None) -> str:
    """Find file with or without relative directory name.

    Parameters
    ----------
    filename : str, optional
        Name of the rule file.
    relative_dirname : str
        Relative directory where the rule file is located.

    Returns
    -------
    str
        Full file path or an empty string if no rule file is located.
    """

    # if the filename doesn't have a relative path, the search is only by name
    # relative_dirname parameter is set to None.
    relative_dirname = relative_dirname.rstrip('/') if relative_dirname else ''
    rules = get_rules_files(filename=[filename],
                                  relative_dirname=relative_dirname).affected_items
    if len(rules) == 0:
        return ''
    elif len(rules) > 1:
        # if many files match the filename criteria,
        # filter rules that starts with rel_dir of the file
        # and from the result, select the rule with the shorter
        # relative path length
        rules = list(filter(lambda x: x['relative_dirname'].startswith(relative_dirname), rules))
        rule = min(rules, key=lambda x: len(x['relative_dirname']))
        return join(common.WAZUH_PATH, rule['relative_dirname'], filename)
    else:
        return normpath(join(common.WAZUH_PATH, rules[0]['relative_dirname'], filename))


def get_rule_file(filename: str = None, raw: bool = False,
                  relative_dirname: str = None) -> Union[str, AffectedItemsWazuhResult]:
    """Read content of specified file.

    Parameters
    ----------
    filename : str, optional
        Name of the rule file.
    raw : bool, optional
        Whether to return the content in raw format (str->XML) or JSON.
        Default `False` (JSON format).
    relative_dirname : str
        Relative directory where the rule file is located.

    Returns
    -------
    str or AffectedItemsWazuhResult
        Content of the file. AffectedItemsWazuhResult format if `raw=False`.
    """
    result = AffectedItemsWazuhResult(none_msg='No rule was returned',
                                      all_msg='Selected rule was returned')

    # if the filename doesn't have a relative path, the search is only by name
    # relative_dirname parameter is set to None.
    full_path = get_rule_file_path(filename, relative_dirname)
    if not full_path:
        result.add_failed_item(id_=filename,
                               error=WazuhError(1415, extra_message=f"{filename}"))
        return result

    try:
        with open(full_path, encoding='utf-8') as file:
            content = file.read()
        if raw:
            result = content
        else:
            # Missing root tag in rule file
            result.affected_items.append(xmltodict.parse(f'<root>{content}</root>')['root'])
            result.total_affected_items = 1
    except ExpatError as exc:
        result.add_failed_item(id_=filename,
                               error=WazuhError(1413, extra_message=f"{filename}: {str(exc)}"))
    except OSError:
        result.add_failed_item(id_=filename,
                               error=WazuhError(1414, extra_message=f"{filename}"))

    return result


def validate_upload_delete_dir(relative_dirname: Union[str, None]) -> Tuple[str, WazuhError]:
    """Validate relative_dirname parameter.

    Parameters
    ----------
    relative_dirname : str
        Relative path to validate.

    Returns
    -------
    Tuple (str, WazuhError)
        The first element of the tuple is the normalized relative path.
            If relative_dirname is None, return USER_RULES_PATH.
            If relative_dirname is not None, return relative_dirname without trailing slash
        The second element of the tuple is a WazuhError exception
            If relative_dirname has no 'rule_dir' tag in ruleset return WazuhError(1505).
            If relative_dirname is inside the default RULES_PATH return WazuhError(1506).
            If relative_dirname has a 'rule_dir' tag in ruleset but it doesn't exists return WazuhError(1507).
            If the path is valid, return None
    """

    ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
    relative_dirname = relative_dirname.rstrip('/') if relative_dirname \
        else to_relative_path(common.USER_RULES_PATH)
    wazuh_error = None
    if relative_dirname not in ruleset_conf['rule_dir']:
        wazuh_error = WazuhError(1209)
    elif commonpath([join(common.WAZUH_PATH, relative_dirname), common.RULES_PATH]) == common.RULES_PATH:
        wazuh_error = WazuhError(1210)
    elif not exists(join(common.WAZUH_PATH, relative_dirname)):
        wazuh_error = WazuhError(1211)
    return relative_dirname, wazuh_error


@expose_resources(actions=['rules:update'], resources=['*:*:*'])
def upload_rule_file(filename: str, content: str, relative_dirname: str = None,
                     overwrite: bool = False) -> AffectedItemsWazuhResult:
    """Upload a new rule file or update an existing one.

    If relative_dirname is not valid, raise an exception.
    If the content is not valid, raise an exception.
    If the rule file is found, update the file if overwrite is true.
    If the rule file is not found, upload a new file.

    Parameters
    ----------
    filename : str, optional
        Name of the rule file.
    content : str, optional
        Content of the file. It must be a valid XML file.
    overwrite : bool, optional
        True for updating existing files. False otherwise. Default `False`
    relative_dirname : str
        Relative directory where the rule file is located.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='Rule was successfully uploaded',
                                      none_msg='Could not upload rule')

    backup_file = ''
    try:
        relative_dirname, wazuh_error = validate_upload_delete_dir(
            relative_dirname=relative_dirname)
        full_path = join(common.WAZUH_PATH, relative_dirname, filename)
        if wazuh_error:
            raise wazuh_error
        if len(content) == 0:
            raise WazuhError(1112)

        validate_wazuh_xml(content)

        # If file already exists and overwrite is False, raise exception
        if not overwrite and exists(full_path):
            raise WazuhError(1905)
        elif overwrite and exists(full_path):
            backup_file = f'{full_path}.backup'
            try:
                full_copy(full_path, backup_file)
            except IOError as exc:
                raise WazuhError(1019) from exc

            delete_rule_file(filename=filename, relative_dirname=relative_dirname)

        upload_file(content, to_relative_path(full_path))

        # After uploading the file, validate it using a logtest dummy msg
        try:
            validate_dummy_logtest()
        except WazuhError as exc:
            if not overwrite and exists(full_path):
                delete_rule_file(filename=filename, relative_dirname=relative_dirname)

            raise exc

        result.affected_items.append(to_relative_path(full_path))
        result.total_affected_items = len(result.affected_items)
        backup_file and exists(backup_file) and remove(backup_file)

    except WazuhError as exc:
        result.add_failed_item(id_=to_relative_path(full_path), error=exc)
    finally:
        exists(backup_file) and safe_move(backup_file, full_path)

    return result


@expose_resources(actions=['rules:delete'], resources=['rule:file:{filename}'])
def delete_rule_file(filename: Union[str, list], relative_dirname: str = None) -> AffectedItemsWazuhResult:
    """Delete a rule file.

    Parameters
    ----------
    filename : str, optional
        Name of the rule file.
    relative_dirname : str
        Relative directory where the rule file is located.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    file = filename if isinstance(filename, str) else filename[0]
    result = AffectedItemsWazuhResult(all_msg='Rule was successfully deleted',
                                      none_msg='Could not delete rule')

    try:
        relative_dirname, wazuh_error = validate_upload_delete_dir(
            relative_dirname=relative_dirname)
        full_path = join(common.WAZUH_PATH, relative_dirname, file)
        if wazuh_error:
            raise wazuh_error

        if exists(full_path):
            try:
                remove(full_path)
                result.affected_items.append(to_relative_path(full_path))
            except IOError as exc:
                raise WazuhError(1907) from exc
        else:
            raise WazuhError(1906)

    except WazuhError as exc:
        result.add_failed_item(id_=to_relative_path(full_path), error=exc)
    result.total_affected_items = len(result.affected_items)

    return result
