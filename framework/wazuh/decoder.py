# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os.path import join, normpath
from typing import Union
from xml.parsers.expat import ExpatError

import xmltodict

from wazuh.core import common
from wazuh.core.decoder import load_decoders_from_file, check_status, REQUIRED_FIELDS, SORT_FIELDS, DECODER_FIELDS
from wazuh.core.exception import WazuhInternalError, WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array
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

#TODO(26356) - To be removed/refactored in other Issue
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
    result = AffectedItemsWazuhResult(all_msg='This feature will be replaced or deleted by new centralized config',
                                      some_msg='This feature will be replaced or deleted by new centralized config',
                                      none_msg='This feature will be replaced or deleted by new centralized config')

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


#TODO(26356) - To be removed/refactored in other Issue
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
    result = AffectedItemsWazuhResult(all_msg='This feature will be replaced or deleted by new centralized config',
                                      some_msg='This feature will be replaced or deleted by new centralized config',
                                      none_msg='This feature will be replaced or deleted by new centralized config')

    return result


#TODO(26356) - To be removed/refactored in other Issue
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
    result = AffectedItemsWazuhResult(all_msg='This feature will be replaced or deleted by new centralized config',
                                      some_msg='This feature will be replaced or deleted by new centralized config',
                                      none_msg='This feature will be replaced or deleted by new centralized config')

    return result
