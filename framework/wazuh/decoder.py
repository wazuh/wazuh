# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import wazuh.core.configuration as configuration
from wazuh.core import common
from wazuh.core.decoder import load_decoders_from_file, check_status, REQUIRED_FIELDS, SORT_FIELDS
from wazuh.core.rule import format_rule_decoder_file
from wazuh.core.exception import WazuhInternalError, WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array


def get_decoders(names=None, status=None, filename=None, relative_dirname=None, parents=False, offset=0,
                 limit=common.database_limit, select=None, sort_by=None, sort_ascending=True, search_text=None,
                 complementary_search=False, search_in_fields=None, q=''):
    """Gets a list of available decoders.

    :param names: Filters by decoder name.
    :param filename: List of filenames to filter by.
    :param status: Filters by status: enabled, disabled, all.
    :param relative_dirname: Filters by relative dirname.
    :param parents: Just parent decoders.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param select: List of selected fields to return
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param q: Defines query to filter.

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(none_msg='No decoder was returned',
                                      some_msg='Some decoders were not returned',
                                      all_msg='All selected decoders were returned')
    all_decoders = list()
    if names is None:
        names = list()

    for decoder_file in get_decoders_files(limit=None).affected_items:
        all_decoders.extend(load_decoders_from_file(decoder_file['filename'], decoder_file['relative_dirname'],
                                                    decoder_file['status']))

    status = check_status(status)
    status = ['enabled', 'disabled'] if status == 'all' else [status]
    parameters = {'relative_dirname': relative_dirname, 'filename': filename, 'name': names, 'parents': parents, 'status': status}
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
                elif key == 'status' and d[key] not in value and d in decoders:
                    decoders.remove(d)
                elif key == 'filename' and d[key] not in filename and d in decoders:
                    decoders.remove(d)
                elif key == 'relative_dirname' and d[key] != relative_dirname and d in decoders:
                    decoders.remove(d)
                elif 'parent' in d['details'] and parents and d in decoders:
                    decoders.remove(d)

    for decoder_name in no_existent_files:
        result.add_failed_item(id_=decoder_name, error=WazuhError(1504))

    data = process_array(decoders, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         allowed_sort_fields=SORT_FIELDS, offset=offset, select=select, limit=limit, q=q,
                         required_fields=REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['decoders:read'], resources=['decoder:file:{filename}'])
def get_decoders_files(status=None, relative_dirname=None, filename=None, offset=0, limit=common.database_limit,
                       sort_by=None, sort_ascending=True, search_text=None, complementary_search=False,
                       search_in_fields=None):
    """Gets a list of the available decoder files.

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
    result = AffectedItemsWazuhResult(none_msg='No decoder files were returned',
                                      some_msg='Some decoder files were not returned',
                                      all_msg='All decoder files were returned')
    status = check_status(status)
    ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
    if not ruleset_conf:
        raise WazuhInternalError(1500)

    decoders_files = list()
    tags = ['decoder_include', 'decoder_exclude', 'decoder_dir']
    if isinstance(filename, list):
        for f in filename:
            decoders_files.extend(format_rule_decoder_file(
                ruleset_conf, {'status': status, 'relative_dirname': relative_dirname, 'filename': f},
                tags))
    else:
        decoders_files = format_rule_decoder_file(
            ruleset_conf,
            {'status': status, 'relative_dirname': relative_dirname, 'filename': filename},
            tags)

    data = process_array(decoders_files, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


def get_file(filename=None):
    """Reads content of specified file

    :param filename: Filename to read content from
    :return: File contents
    """
    decoders = get_decoders_files(filename=filename).affected_items

    if len(decoders) > 0:
        decoder_path = decoders[0]['relative_dirname']
        try:
            full_path = os.path.join(common.ossec_path, decoder_path, filename)
            with open(full_path) as f:
                file_content = f.read()
            return file_content
        except OSError:
            raise WazuhError(1502, extra_message=os.path.join('WAZUH_HOME', decoder_path, filename))
        except Exception:
            raise WazuhInternalError(1501, extra_message=os.path.join('WAZUH_HOME', decoder_path, filename))
    else:
        raise WazuhError(1503)
