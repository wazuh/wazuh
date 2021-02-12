# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from os import remove
from os.path import join, exists
from typing import Union
from xml.parsers.expat import ExpatError

import xmltodict

import wazuh.core.configuration as configuration
from wazuh.core import common
from wazuh.core.decoder import load_decoders_from_file, check_status, REQUIRED_FIELDS, SORT_FIELDS
from wazuh.core.exception import WazuhInternalError, WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.rule import format_rule_decoder_file
from wazuh.core.utils import process_array, safe_move, validate_wazuh_xml, \
    delete_file_with_backup, upload_file, to_relative_path
from wazuh.rbac.decorators import expose_resources


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


def get_decoder_file(filename: str, raw: bool = False) -> Union[str, AffectedItemsWazuhResult]:
    """Read content of specified file.

    Parameters
    ----------
    filename : str
        Name of the decoder file.
    raw : bool
        Whether to return the content in raw format (str->XML) or JSON.

    Returns
    -------
    str or dict
        Content of the file. AffectedItemsWazuhResult format if `raw=False`.
    """
    result = AffectedItemsWazuhResult(none_msg='No decoder was returned',
                                      all_msg='Selected decoder was returned')
    decoders = get_decoders_files(filename=filename).affected_items

    if len(decoders) > 0:
        decoder_path = decoders[0]['relative_dirname']
        try:
            full_path = join(common.ossec_path, decoder_path, filename)
            with open(full_path) as f:
                file_content = f.read()
            if raw:
                result = file_content
            else:
                # Missing root tag in decoder file
                result.affected_items.append(xmltodict.parse(f'<root>{file_content}</root>')['root'])
                result.total_affected_items = 1
        except ExpatError as e:
            result.add_failed_item(id_=filename,
                                   error=WazuhError(1501, extra_message=f"{join('WAZUH_HOME', decoder_path, filename)}:"     
                                                                        f" {str(e)}"))
        except OSError:
            result.add_failed_item(id_=filename,
                                   error=WazuhError(1502, extra_message=join('WAZUH_HOME', decoder_path, filename)))

    else:
        result.add_failed_item(id_=filename, error=WazuhError(1503))

    return result


@expose_resources(actions=['decoders:update'], resources=['*:*:*'])
def upload_decoder_file(filename: str, content: str, overwrite: bool = False) -> AffectedItemsWazuhResult:
    """Upload a new decoder file or update an existing one.

    Parameters
    ----------
    filename : str
        Name of the decoder file.
    content : str
        Content of the file. It must be a valid XML file.
    overwrite : bool
        True for updating existing files. False otherwise.

    Returns
    -------
    AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='Decoder was successfully uploaded',
                                      none_msg='Could not upload decoder'
                                      )
    full_path = join(common.user_decoders_path, filename)
    backup_file = ''
    try:
        if len(content) == 0:
            raise WazuhError(1112)

        validate_wazuh_xml(content)
        # If file already exists and overwrite is False, raise exception
        if not overwrite and exists(full_path):
            raise WazuhError(1905)
        elif overwrite and exists(full_path):
            backup_file = f'{full_path}.backup'
            delete_file_with_backup(backup_file, full_path, delete_decoder_file)

        upload_file(content, to_relative_path(full_path))
        result.affected_items.append(to_relative_path(full_path))
        result.total_affected_items = len(result.affected_items)
        backup_file and exists(backup_file) and remove(backup_file)
    except WazuhError as e:
        result.add_failed_item(id_=to_relative_path(full_path), error=e)
    finally:
        exists(backup_file) and safe_move(backup_file, full_path, permissions=0o0660)

    return result


@expose_resources(actions=['decoders:delete'], resources=['decoder:file:{filename}'])
def delete_decoder_file(filename: str) -> AffectedItemsWazuhResult:
    """Delete a decoder file.

    Parameters
    ----------
    filename : str
        Name of the decoder file.

    Returns
    -------
    AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='Decoder file was successfully deleted',
                                      none_msg='Could not delete decoder file'
                                      )

    full_path = join(common.user_decoders_path, filename[0])

    try:
        if exists(full_path):
            try:
                remove(full_path)
                result.affected_items.append(to_relative_path(full_path))
            except IOError:
                raise WazuhError(1907)
        else:
            raise WazuhError(1906)
    except WazuhError as e:
        result.add_failed_item(id_=to_relative_path(full_path), error=e)
    result.total_affected_items = len(result.affected_items)

    return result
