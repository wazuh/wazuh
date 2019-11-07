# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import wazuh.configuration as configuration
from wazuh import common
from wazuh.core.decoder import load_decoders_from_file, check_status, Status
from wazuh.core.rule import format_rule_decoder_file
from wazuh.exception import WazuhInternalError, WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.results import AffectedItemsWazuhResult
from wazuh.utils import process_array


def get_decoders(names=None, status=None, file=None, path=None, parents=False, offset=0,
                 limit=common.database_limit, sort_by=None, sort_ascending=True, search_text=None,
                 complementary_search=False, search_in_fields=None, q=''):
    """Gets a list of available decoders.

    :param names: Filters by decoder name.
    :param file: Filters by file.
    :param status: Filters by status: enabled, disabled, all.
    :param path: Filters by path.
    :param parents: Just parent decoders.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param q: Defines query to filter.

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(none_msg='No decoder was shown',
                                      some_msg='Some decoders could not be shown',
                                      all_msg='All selected decoders were shown')
    status = check_status(status)
    all_decoders = list()
    if names is None:
        names = list()

    for decoder_file in get_decoders_files(status=status, limit=None).affected_items:
        all_decoders.extend(load_decoders_from_file(decoder_file['file'], decoder_file['path'],
                                                    decoder_file['status']))

    parameters = {'path': path, 'file': file, 'name': names, 'parents': parents}
    decoders = list(all_decoders)
    no_existent_files = names[:]
    for d in all_decoders:
        for key, value in parameters.items():
            if value:
                if key == 'name':
                    if d[key] not in value and d in decoders:
                        decoders.remove(d)
                    elif d[key] in no_existent_files:
                        no_existent_files.remove(d[key])
                elif key == 'file' and d[key] not in file and d in decoders:
                    decoders.remove(d)
                elif key == 'path' and d[key] != path and d in decoders:
                    decoders.remove(d)
                elif 'parent' in d['details'] and parents and d in decoders:
                    decoders.remove(d)
    for decoder_name in no_existent_files:
        result.add_failed_item(id_=decoder_name, error=WazuhError(1504))

    result.affected_items = process_array(
        decoders, search_text=search_text, search_in_fields=search_in_fields, complementary_search=complementary_search,
        sort_by=sort_by, sort_ascending=sort_ascending, allowed_sort_fields=Status.SORT_FIELDS.value, offset=offset,
        limit=limit, q=q)['items']
    result.total_affected_items = len(decoders)

    return result


@expose_resources(actions=['decoders:read'], resources=['decoder:file:{file}'])
def get_decoders_files(status=None, path=None, file=None, offset=0, limit=common.database_limit, sort_by=None,
                       sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Gets a list of the available decoder files.

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
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(none_msg='No rules files were shown',
                                      some_msg='Some rules files were shown',
                                      all_msg='All rules files were shown')
    status = check_status(status)
    ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
    if not ruleset_conf:
        raise WazuhInternalError(1500)

    decoders_files = list()
    tags = ['decoder_include', 'decoder_exclude', 'decoder_dir']
    if isinstance(file, list):
        for f in file:
            decoders_files.extend(
                format_rule_decoder_file(ruleset_conf, {'status': status, 'path': path, 'file': f}, tags))
    else:
        decoders_files = format_rule_decoder_file(ruleset_conf, {'status': status, 'path': path, 'file': file}, tags)
    result.affected_items = process_array(decoders_files, search_text=search_text, search_in_fields=search_in_fields,
                                          complementary_search=complementary_search, sort_by=sort_by,
                                          sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.total_affected_items = len(decoders_files)

    return result


def get_file(file=None):
    """Reads content of specified file

    :param file: File name to read content from
    :return: File contents
    """
    decoders = get_decoders_files(file=file).affected_items

    if len(decoders) > 0:
        decoder_path = decoders[0]['path']
        try:
            full_path = os.path.join(common.ossec_path, decoder_path, file)
            with open(full_path) as f:
                file_content = f.read()
            return file_content
        except OSError:
            raise WazuhError(1502, extra_message=os.path.join('WAZUH_HOME', decoder_path, file))
        except Exception:
            raise WazuhInternalError(1501, extra_message=os.path.join('WAZUH_HOME', decoder_path, file))
    else:
        raise WazuhError(1503)
