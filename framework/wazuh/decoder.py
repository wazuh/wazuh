# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import remove
from os.path import join, exists, normpath, commonpath
from typing import Union, Tuple
from xml.parsers.expat import ExpatError

import xmltodict

import wazuh.core.configuration as configuration
from wazuh.core import common
from wazuh.core.analysis import send_reload_ruleset_msg
from wazuh.core.decoder import load_decoders_from_file, check_status, REQUIRED_FIELDS, SORT_FIELDS, DECODER_FIELDS, \
    DECODER_FILES_FIELDS, DECODER_FILES_REQUIRED_FIELDS
from wazuh.core.exception import WazuhInternalError, WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.rule import format_rule_decoder_file
from wazuh.core.utils import process_array, safe_move, validate_wazuh_xml, \
    upload_file, to_relative_path, full_copy
from wazuh.core.logtest import validate_dummy_logtest
from wazuh.rbac.decorators import expose_resources


def get_decoders(names: list = None, status: str = None, filename: list = None, relative_dirname: str = None,
                 parents: bool = False, offset: int = 0, limit: int = common.DATABASE_LIMIT, select: list = None,
                 sort_by: list = None, sort_ascending: bool = True, search_text: str = None,
                 complementary_search: bool = False, search_in_fields: list = None,
                 q: str = '', distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get a list of available decoders.

    Parameters
    ----------
    names : list
        Filters by decoder name.
    filename : list
        List of filenames to filter by.
    status : str
        Filters by status: enabled, disabled, all.
    parents : bool
        Just parent decoders.
    relative_dirname : str
        Filters by relative dirname.
    search_text : str
        Text to search.
    complementary_search : bool
        Find items without the text to search. Default: False
    search_in_fields : list
        Fields to search in.
    select : list
        List of selected fields to return
    sort_by : list
        Fields to sort the items by.
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order. Default: True
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    q : str
        Defines query to filter.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
    parameters = {'relative_dirname': relative_dirname, 'filename': filename, 'name': names, 'parents': parents,
                  'status': status}
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
                         required_fields=REQUIRED_FIELDS, allowed_select_fields=DECODER_FIELDS, distinct=distinct)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['decoders:read'], resources=['decoder:file:{filename}'])
def get_decoders_files(status: str = None, relative_dirname: str = None, filename: list = None, offset: int = 0,
                       limit: int = common.DATABASE_LIMIT, sort_by: list = None, sort_ascending: bool = True,
                       search_text: str = None, complementary_search: bool = False,
                       search_in_fields: list = None, q: str = None, select: str = None,
                       distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get a list of the available decoder files.

    Parameters
    ----------
    filename : list
        List of filenames to filter by.
    status : str
        Filters by status: enabled, disabled, all.
    relative_dirname : str
        Filters by relative dirname.
    search_text : str
        Text to search.
    complementary_search : bool
        Find items without the text to search. Default: False
    search_in_fields : list
        Fields to search in.
    sort_by : list
        Fields to sort the items by.
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order. Default: True
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhInternalError(1500)
        Error reading decoders from ossec.conf.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
                         offset=offset, limit=limit, q=q, select=select, allowed_select_fields=DECODER_FILES_FIELDS,
                         distinct=distinct, required_fields=DECODER_FILES_REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


def get_decoder_file_path(filename: str,
                          relative_dirname: str = None) -> str:
    """Find decoder file with or without relative directory name.

    Parameters
    ----------
    filename : str, optional
        Name of the decoder file.
    relative_dirname : str
        Relative directory where the decoder file is located.

    Returns
    -------
    str
        Full file path or an empty string if no decoder file is located.
    """

    # if the filename doesn't have a relative path, the search is only by name
    # relative_dirname parameter is set to None.
    relative_dirname = relative_dirname.rstrip('/') if relative_dirname else None
    decoders = get_decoders_files(filename=filename,
                                  relative_dirname=relative_dirname).affected_items
    if len(decoders) == 0:
        return ''
    elif len(decoders) > 1:
        # if many files match the filename criteria, 
        # filter decoders that starts with rel_dir of the file
        # and from the result, select the decoder with the shorter
        # relative path length
        relative_dirname = relative_dirname if relative_dirname else ''
        decoders = list(filter(lambda x: x['relative_dirname'].startswith(
            relative_dirname), decoders))
        decoder = min(decoders, key=lambda x: len(x['relative_dirname']))
        return join(common.WAZUH_PATH, decoder['relative_dirname'], filename)
    else:
        return normpath(join(common.WAZUH_PATH, decoders[0]['relative_dirname'], filename))


def get_decoder_file(filename: str, raw: bool = False,
                     relative_dirname: str = None) -> Union[str, AffectedItemsWazuhResult]:
    """Read content of a specified file.

    Parameters
    ----------
    filename : list. Mandatory.
        List of one element with the complete relative path of the decoder file.
    raw : bool
        Whether to return the content in raw format (str->XML) or JSON.
    relative_dirname : str
        Relative directory where the decoder file is located.

    Returns
    -------
    str or AffectedItemsWazuhResult
        Content of the file. AffectedItemsWazuhResult format if `raw=False`.
    """
    result = AffectedItemsWazuhResult(none_msg='No decoder was returned',
                                      all_msg='Selected decoder was returned')

    full_path = get_decoder_file_path(filename, relative_dirname)
    if not full_path:
        result.add_failed_item(id_=filename,
                               error=WazuhError(1503, extra_message=f"{filename}"))
        return result

    try:
        with open(full_path, encoding='utf-8') as file:
            file_content = file.read()
        if raw:
            result = file_content
        else:
            # Missing root tag in decoder file
            result.affected_items.append(xmltodict.parse(f'<root>{file_content}</root>')['root'])
            result.total_affected_items = 1
    except ExpatError as exc:
        result.add_failed_item(id_=filename,
                               error=WazuhError(1501, extra_message=f"{filename}: {str(exc)}"))
    except OSError:
        result.add_failed_item(id_=filename,
                               error=WazuhError(1502, extra_message=f"{filename}"))

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
            If relative_dirname is None, return USER_DECODERS_PATH.
            If relative_dirname is not None, return relative_dirname without trailing slash
        The second element of the tuple is a WazuhError exception.
            If relative_dirname has no 'decoder_dir' tag in ruleset return WazuhError(1505).
            If relative_dirname is inside the default DECODERS_PATH return WazuhError(1506).
            If relative_dirname has a 'decoder_dir' tag in ruleset but it doesn't exists return WazuhError(1507).
            If the path is valid, return None
    """

    ruleset_conf = configuration.get_ossec_conf(section='ruleset')['ruleset']
    relative_dirname = relative_dirname.rstrip('/') if relative_dirname \
        else to_relative_path(common.USER_DECODERS_PATH)
    wazuh_error = None
    if not relative_dirname in ruleset_conf['decoder_dir']:
        wazuh_error = WazuhError(1505)
    elif commonpath([join(common.WAZUH_PATH, relative_dirname), common.DECODERS_PATH]) == common.DECODERS_PATH:
        wazuh_error = WazuhError(1506)
    elif not exists(join(common.WAZUH_PATH, relative_dirname)):
        wazuh_error = WazuhError(1507)
    return relative_dirname, wazuh_error


@expose_resources(actions=['decoders:update'], resources=['*:*:*'])
def upload_decoder_file(filename: str, content: str, relative_dirname: str = None,
                        overwrite: bool = False) -> AffectedItemsWazuhResult:
    """Upload a new decoder file or update an existing one.
    
    If relative_dirname is not valid, raise an exception.
    If the content is not valid, raise an exception.
    If the decoder file is found, update the file if overwrite is true.
    If the decoder file is not found, upload a new file.

    Parameters
    ----------
    filename : str
        Name of the decoder file.
    content : str
        Content of the file. It must be a valid XML file.
    relative_dirname : str
        Relative directory where the decoder is located.
    overwrite : bool
        True for updating existing files. False otherwise.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='Decoder was successfully uploaded',
                                      none_msg='Could not upload decoder'
                                      )
    backup_file = ''
    try:
        relative_dirname, wazuh_error = validate_upload_delete_dir(relative_dirname=relative_dirname)
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

            delete_decoder_file(filename=filename,
                                relative_dirname=relative_dirname)

        upload_file(content, to_relative_path(full_path))

        # After uploading the file, validate it using a logtest dummy msg
        try:
            validate_dummy_logtest()
        except WazuhError as exc:
            if not overwrite and exists(full_path):
                delete_decoder_file(filename=filename, relative_dirname=relative_dirname)

            raise exc

        # After uploading the file, reload rulesets
        socket_response = send_reload_ruleset_msg(origin={'module': 'api'})
        if socket_response.is_ok():
            if socket_response.has_warnings():
                result.all_msg(','.join(socket_response.warnings))
        else:
            raise WazuhError(1508, extra_message=','.join(socket_response.errors))

        result.affected_items.append(to_relative_path(full_path))
        result.total_affected_items = len(result.affected_items)
        backup_file and exists(backup_file) and remove(backup_file)
    except WazuhError as exc:
        result.add_failed_item(id_=to_relative_path(full_path), error=exc)
    finally:
        exists(backup_file) and safe_move(backup_file, full_path)

    return result


@expose_resources(actions=['decoders:delete'], resources=['decoder:file:{filename}'])
def delete_decoder_file(filename: Union[str, list], relative_dirname: str = None) -> AffectedItemsWazuhResult:
    """Delete a decoder file.

    If relative_dirname is not valid, raise an exception
    If the file does not exist, raise an exception

    Parameters
    ----------
    filename : str
        Name of the decoder file.
    relative_dirname : str
        Relative directory where the decoder file is located.
        
    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    file = filename[0] if isinstance(filename, list) else filename

    result = AffectedItemsWazuhResult(all_msg='Decoder file was successfully deleted',
                                      none_msg='Could not delete decoder file')
    try:
        relative_dirname, wazuh_error = validate_upload_delete_dir(relative_dirname=relative_dirname)
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

        # After deleting the file, reload rulesets
        socket_response = send_reload_ruleset_msg(origin={'module': 'api'})
        if socket_response.is_ok():
            if socket_response.has_warnings():
                result.all_msg(','.join(socket_response.warnings))
        else:
            raise WazuhError(1508, extra_message=','.join(socket_response.errors))

    except WazuhError as exc:
        result.add_failed_item(id_=to_relative_path(full_path), error=exc)
    result.total_affected_items = len(result.affected_items)

    return result
