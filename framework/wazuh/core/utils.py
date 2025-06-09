# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import errno
import glob
import hashlib
import json
import operator
import os
import re
import stat
import sys
import tempfile
import typing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from functools import wraps
from itertools import groupby, chain
from os import chmod, chown, listdir, mkdir, curdir, rename, utime, remove, walk, path
import psutil
from pyexpat import ExpatError
from requests import get, exceptions
from shutil import Error, move, copy2
from signal import signal, alarm, SIGALRM, SIGKILL

from cachetools import cached, TTLCache
from defusedxml.ElementTree import fromstring
from defusedxml.minidom import parseString

import wazuh.core.results as results
from api import configuration
from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.wdb import WazuhDBConnection

# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str

# Temporary cache
t_cache = TTLCache(maxsize=4500, ttl=60)


def clean_pid_files(daemon: str) -> None:
    """Check the existence of '.pid' files for a specified daemon.

    Parameters
    ----------
    daemon : str
        Daemon's name.
    """
    regex = rf'{daemon}[\w_]*-(\d+).pid'
    for pid_file in os.listdir(common.OSSEC_PIDFILE_PATH):
        if match := re.match(regex, pid_file):
            try:
                pid = int(match.group(1))
                process = psutil.Process(pid)
                command = process.cmdline()[-1]

                if daemon.replace('-', '_') in command:
                    os.kill(pid, SIGKILL)
                    print(f"{daemon}: Orphan child process {pid} was terminated.")
                else:
                    print(f"{daemon}: Process {pid} does not belong to {daemon}, removing from {common.WAZUH_PATH}/var/run...")

            except (OSError, psutil.NoSuchProcess):
                print(f'{daemon}: Non existent process {pid}, removing from {common.WAZUH_PATH}/var/run...')
            finally:
                os.remove(path.join(common.OSSEC_PIDFILE_PATH, pid_file))


def find_nth(string: str, substring: str, n: int) -> int:
    """Return the index corresponding to the n'th occurrence of a substring within a string.

    Parameters
    ----------
    string : str
        String where the substring is searched.
    substring : str
        String to be found in "string".
    n : int
        Occurrence to be found.

    Returns
    -------
    int
        Index of the n'th occurrence of a substring within a string.
    """

    start = string.find(substring)
    while start >= 0 and n > 1:
        start = string.find(substring, start + len(substring))
        n -= 1
    return start


def previous_month(n: int = 1) -> datetime.date:
    """Return the first date of the previous n month.

    Parameters
    ----------
    n : int
        Number of months.

    Returns
    -------
    datetime.date
        First date of the previous n month.
    """

    date = get_utc_now().replace(day=1)  # First day of current month

    for i in range(0, int(n)):
        date = (date - timedelta(days=1)).replace(day=1)  # (first_day - 1) = previous month

    return date.replace(hour=00, minute=00, second=00, microsecond=00)


def process_array(array: list, search_text: str = None, complementary_search: bool = False,
                  search_in_fields: list = None, select: list = None, sort_by: list = None,
                  sort_ascending: bool = True, allowed_sort_fields: list = None, offset: int = 0, limit: int = None,
                  q: str = '', required_fields: list = None, allowed_select_fields: list = None,
                  filters: dict = None, distinct: bool = False) -> dict:
    """Process a Wazuh framework data array.

    Parameters
    ----------
    array : list
        Array to process.
    search_text : str
        Text to search and search type.
    complementary_search : bool
        Perform a complementary search.
    search_in_fields : list
        Fields to search in.
    select : list
        Select fields to return.
    sort_by : list
        Fields to sort_by. Will sort the array directly if [''] is received.
    sort_ascending : bool
        Sort order ascending or descending.
    allowed_sort_fields : list
        Allowed fields to sort_by.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    q : str
        Query to filter by.
    required_fields : list
        Required fields that must appear in the response.
    allowed_select_fields: list
        List of fields allowed to select from.
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    distinct : bool
        Look for distinct values.

    Returns
    -------
    dict
        Dictionary: {'items': Processed array, 'totalItems': Number of items, before applying offset and limit)}
    """
    if not array:
        return {'items': [], 'totalItems': 0}
    
    if isinstance(filters, dict) and len(filters.keys()) > 0:
        new_array = []
        for element in array:
            for key, value in filters.items():
                if element[key] in value:
                    new_array.append(element)
                    break

        array = new_array

    if sort_by == [""]:
        array = sort_array(array, sort_ascending=sort_ascending)
    elif sort_by:
        array = sort_array(array, sort_by=sort_by, sort_ascending=sort_ascending,
                           allowed_sort_fields=allowed_sort_fields)

    if search_text:
        array = search_array(array, search_text=search_text, complementary_search=complementary_search,
                             search_in_fields=search_in_fields)

    if q:
        array = filter_array_by_query(q, array)

    if select:
        # Do not force the inclusion of any fields when we are looking for distinct values
        required_fields = set() if distinct else required_fields
        array = select_array(array, select=select, required_fields=required_fields,
                             allowed_select_fields=allowed_select_fields)

    if distinct:
        distinct_array = []
        for element in array:
            if element not in distinct_array:
                distinct_array.append(element)

        array = distinct_array

    return {'items': cut_array(array, offset=offset, limit=limit), 'totalItems': len(array)}


def cut_array(array: list, offset: int = 0, limit: int = common.DATABASE_LIMIT) -> list:
    """Return a part of the array: from offset to offset + limit.

    Parameters
    ----------
    array : list
        Array to cut.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return. 0 means no cut array.

    Raises
    ------
    WazuhError(1400)
        Invalid offset.
    WazuhError(1401)
        Invalid limit.
    WazuhError(1405)
        Limit exceeding the maximum permitted.
    WazuhError(1406)
        Invalid limit (0).

    Returns
    -------
    list
        Cut array.
    """

    if limit is not None:
        if limit > common.MAXIMUM_DATABASE_LIMIT:
            raise WazuhError(1405, extra_message=str(limit))
        elif limit == 0:
            raise WazuhError(1406)

    elif not array or limit is None:
        return array

    offset = int(offset)
    limit = int(limit)

    if offset < 0:
        raise WazuhError(1400)
    elif limit < 1:
        raise WazuhError(1401)
    else:
        return array[offset:offset + limit]


def sort_array(array: list, sort_by: list = None, sort_ascending: bool = True,
               allowed_sort_fields: list = None) -> list:
    """Sort an array.

    Parameters
    ----------
    array : list
        Array to sort.
    sort_by : list
        Array of fields.
    sort_ascending : bool
        Ascending if true and descending if false.
    allowed_sort_fields : list
        Check sort_by with allowed_sort_fields (array).

    Raises
    ------
    WazuhError(1403)
        Not a valid sort field.
    WazuhError(1402)
        Invalid sort_ascending field.

    Returns
    -------
    list
        Sorted array.
    """

    def check_sort_fields(allowed_sort_fields, sort_by):
        # Check if every element in sort['fields'] is in allowed_sort_fields
        if not sort_by.issubset(allowed_sort_fields):
            incorrect_fields = ', '.join(sort_by - allowed_sort_fields)
            raise WazuhError(1403, extra_remediation='Allowed sort fields: {0}. '
                                                     'Wrong fields: {1}'.format(', '.join(allowed_sort_fields),
                                                                                incorrect_fields))

    if not array:
        return array

    if not isinstance(sort_ascending, bool):
        raise WazuhError(1402)

    is_sort_valid = False
    if allowed_sort_fields:
        check_sort_fields(set(allowed_sort_fields), set(sort_by))
        is_sort_valid = True

    if sort_by:  # array should be a dictionary or a Class
        if type(array[0]) is dict:
            not is_sort_valid and check_sort_fields(set(array[0].keys()), set(sort_by))
            try:
                return sorted(array,
                              key=lambda o: tuple(
                                  o.get(a).lower() if type(o.get(a)) in (str, unicode) else o.get(a) for a in sort_by),
                              reverse=not sort_ascending)
            except TypeError:
                items_with_missing_keys = list()
                copy_array = deepcopy(array)
                for item in array:
                    set(sort_by) & set(item.keys()) and items_with_missing_keys.append(
                        copy_array.pop(copy_array.index(item)))

                sorted_array = sorted(copy_array, key=lambda o: tuple(
                    o.get(a).lower() if type(o.get(a)) in (str, unicode) else o.get(a) for a in sort_by),
                                      reverse=not sort_ascending)

                if not sort_ascending:
                    items_with_missing_keys.extend(sorted_array)
                    return items_with_missing_keys
                else:
                    sorted_array.extend(items_with_missing_keys)
                    return sorted_array

        else:
            return sorted(array,
                          key=lambda o: tuple(
                              getattr(o, a).lower() if type(getattr(o, a)) in (str, unicode) else getattr(o, a)
                              for a in sort_by),
                          reverse=not sort_ascending)
    else:
        if type(array) is set or (type(array[0]) is not dict and 'class \'wazuh' not in str(type(array[0]))):
            return sorted(array, reverse=not sort_ascending)
        else:
            return array


def get_values(o: object, fields: list = None) -> list:
    """Convert the values of an object to an array of strings.

    Parameters
    ----------
    o : object
        Object.
    fields : list
        Fields to get values of (only for dictionaries).

    Returns
    -------
    list
        Array of strings.
    """
    strings = []

    try:
        obj = o.to_dict()  # Rule, Decoder, Agent...
    except:
        obj = o

    if type(obj) is list:
        for o in obj:
            strings.extend(get_values(o))
    elif type(obj) is dict:
        for key in obj:
            if not fields or key in fields:
                strings.extend(get_values(obj[key]))
    else:
        strings.append(obj.lower() if isinstance(obj, str) or isinstance(obj, unicode) else str(obj))

    return strings


def search_array(array, search_text: str = None, complementary_search: bool = False,
                 search_in_fields: list = None) -> list:
    """Look for the string 'text' in the elements of the array.

    Parameters
    ----------
    array : list
        Array.
    search_text : str
        Text to search.
    complementary_search : bool
        The text must not be in the array.
    search_in_fields : list
        Fields of the array to search in.

    Returns
    -------
    list
        Filtered array.
    """

    found = []

    for item in array:

        values = get_values(o=item, fields=search_in_fields)

        if not complementary_search:
            for v in values:
                if search_text.lower() in v:
                    found.append(item)
                    break
        else:
            not_in_values = True
            for v in values:
                if search_text.lower() in v:
                    not_in_values = False
                    break
            if not_in_values:
                found.append(item)

    return found


def select_array(array: list, select: list = None, required_fields: set = None,
                 allowed_select_fields: list = None) -> list:
    """Get only those values from each element in the array that matches the select values.

    Parameters
    ----------
    array : list
        Array of elements. It contains all the results without any filter.
    select : list of str, optional
        List of select fields. These can be nested fields of n depth levels. Default `None`
        Example: ['select1', 'select2.select21.select22', 'select3.select31']
    required_fields : set, optional
        Set of fields that must be in the response. These depends on the framework function.
    allowed_select_fields: list
        List of fields allowed to select from.

    Raises
    ------
    WazuhError(1724)
        Raise this exception when at least one of the select fields is not valid.

    Returns
    -------
    result_list : list
        Filtered array of dicts with only the selected (and required) fields as keys.
    """

    def get_nested_fields(dikt, select_field):
        split_select = select_field.split('.')
        if len(split_select) == 1:
            try:
                last_field = {select_field: dikt[select_field]}
            except (KeyError, TypeError):
                last_field = None
            return last_field
        else:
            try:
                next_element = get_nested_fields(dikt[split_select[0]], '.'.join(split_select[1:]))
            except (KeyError, TypeError):
                next_element = None
            return {split_select[0]: next_element} if next_element else None

    def detect_nested_select(user_select):
        nested = set()
        no_nested = set()
        for element in user_select:
            no_nested.add(element) if '.' not in element else nested.add(element)

        return nested, no_nested

    if required_fields is None:
        required_fields = set()

    select_nested, select_no_nested = detect_nested_select(set(select))
    if allowed_select_fields and not select_no_nested.issubset(allowed_select_fields):
        raise WazuhError(1724, "{}".format(', '.join(select_no_nested)))
    select = select_nested.union(select_no_nested)

    result_list = list()
    for item in array:
        selected_fields = dict()
        # Build an entry with the filtered values
        for sel in select:
            candidate = get_nested_fields(item, sel)
            if candidate:
                selected_fields.update(candidate)
        # Add required fields if the entry is not empty
        if array and not allowed_select_fields and not selected_fields:
            raise WazuhError(1724, "{}".format(', '.join(select)))
        selected_fields.update({req_field: item[req_field] for req_field in required_fields})
        result_list.append(selected_fields)

    return result_list


_filemode_table = (
    ((stat.S_IFLNK, "l"),
     (stat.S_IFREG, "-"),
     (stat.S_IFBLK, "b"),
     (stat.S_IFDIR, "d"),
     (stat.S_IFCHR, "c"),
     (stat.S_IFIFO, "p")),

    ((stat.S_IRUSR, "r"),),
    ((stat.S_IWUSR, "w"),),
    ((stat.S_IXUSR | stat.S_ISUID, "s"),
     (stat.S_ISUID, "S"),
     (stat.S_IXUSR, "x")),

    ((stat.S_IRGRP, "r"),),
    ((stat.S_IWGRP, "w"),),
    ((stat.S_IXGRP | stat.S_ISGID, "s"),
     (stat.S_ISGID, "S"),
     (stat.S_IXGRP, "x")),

    ((stat.S_IROTH, "r"),),
    ((stat.S_IWOTH, "w"),),
    ((stat.S_IXOTH | stat.S_ISVTX, "t"),
     (stat.S_ISVTX, "T"),
     (stat.S_IXOTH, "x"))
)


def filemode(mode: int) -> str:
    """Convert a file's mode to a string of the form '-rwxrwxrwx'.

    Parameters
    ----------
    mode : int
        Mode.

    Returns
    -------
    str
        String.
    """
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)


def tail(filename: str, n: int = 20) -> list:
    """Returns last 'n' lines of the file 'filename'.

    Parameters
    ----------
    filename : str
        Path to the file.
    n : int
        Number of lines.

    Returns
    -------
    list
        Array of last lines.
    """
    with open(filename, 'rb') as f:
        total_lines_wanted = n

        BLOCK_SIZE = 1024
        f.seek(0, 2)
        block_end_byte = f.tell()
        lines_to_go = total_lines_wanted
        block_number = -1
        blocks = []  # blocks of size BLOCK_SIZE, in reverse order starting from the end of the file
        while lines_to_go > 0 and block_end_byte > 0:
            if (block_end_byte - BLOCK_SIZE > 0):
                # read the last block we haven't yet read
                f.seek(block_number * BLOCK_SIZE, 2)
                blocks.append(f.read(BLOCK_SIZE).decode('utf-8', errors='replace'))
            else:
                # file too small, start from beginning
                f.seek(0, 0)
                # only read what was not read
                blocks.append(f.read(block_end_byte).decode('utf-8', errors='replace'))
            lines_found = blocks[-1].count('\n')
            lines_to_go -= lines_found
            block_end_byte -= BLOCK_SIZE
            block_number -= 1
        all_read_text = ''.join(reversed(blocks))

    return all_read_text.splitlines()[-total_lines_wanted:]


def chmod_r(file_path: str, mode: int):
    """Recursive chmod.

    Parameters
    ----------
    file_path: str
        Path to the file.
    mode: int
        File mode in octal.
    """

    if path.isdir(file_path):
        for item in listdir(file_path):
            item_path = path.join(file_path, item)
            if path.isfile(item_path):
                chmod(item_path, mode)
            elif path.isdir(item_path):
                chmod_r(item_path, mode)

    chmod(file_path, mode)


def chown_r(file_path: str, uid: int, gid: int):
    """Recursive chown.

    Parameters
    ----------
    file_path: str
        Path to the file.
    uid: int
        User ID.
    gid: int
        Group ID.
    """
    chown(file_path, uid, gid)

    if path.isdir(file_path):
        for item in listdir(file_path):
            item_path = path.join(file_path, item)
            if path.isfile(item_path):
                chown(item_path, uid, gid)
            elif path.isdir(item_path):
                chown_r(item_path, uid, gid)


def delete_wazuh_file(full_path: str) -> bool:
    """Delete a Wazuh file.

    Parameters
    ----------
    full_path : str
        Full path of the file to delete.

    Raises
    ------
    WazuhError(1906)
        File does not exist.
    WazuhError(1907)
        File could not be deleted.

    Returns
    -------
    bool
        True if success.
    """
    if not full_path.startswith(common.WAZUH_PATH) or '..' in full_path:
        raise WazuhError(1907)

    if path.exists(full_path):
        try:
            remove(full_path)
            return True
        except IOError:
            raise WazuhError(1907)
    else:
        raise WazuhError(1906)


def safe_move(source: str, target: str, ownership: tuple = None, time: tuple = None, permissions: int = None):
    """Move a file even between filesystems

    This function is useful to move files even when target directory is in a different filesystem from the source.
    Write permissions are required on target directory.

    Parameters
    ----------
    source : str
        Full path to source file.
    target : str
        Full path to target file.
    ownership : tuple
        Tuple in the form (user, group) to be set up after the file is moved.
    time : tuple
        Tuple in the form (addition_timestamp, modified_timestamp).
    permissions : int
        String mask in octal notation. I.e.: 0o640.
    """
    # Create temp file. Move between
    tmp_path, tmp_filename = path.split(target)
    tmp_target = path.join(tmp_path, f".{tmp_filename}.tmp")
    move(source, tmp_target, copy_function=full_copy)

    # Set up metadata
    if ownership is not None:
        chown(tmp_target, *ownership)
    if permissions is not None:
        chmod(tmp_target, permissions)
    if time is not None:
        utime(tmp_target, time)

    try:
        # Overwrite the file atomically.
        rename(tmp_target, target)
    except OSError:
        # This is the last try when target is still in a different filesystem.
        # For example, when target is a mounted file in a Docker container
        # However, this is not an atomic operation and could lead to race conditions
        # if the file is read/written simultaneously with other processes
        move(tmp_target, target, copy_function=full_copy)


def mkdir_with_mode(name: str, mode: int = 0o770):
    """Create a directory with specified permissions.

    Parameters
    ----------
    name : str
        Directory path.
    mode : int
        Permissions to set to the directory.
    """
    head, tail = path.split(name)
    if not tail:
        head, tail = path.split(head)
    if head and tail and not path.exists(head):
        try:
            mkdir_with_mode(head, mode)
        except OSError as e:
            # be happy if someone already created the path
            if e.errno != errno.EEXIST:
                raise
        if tail == curdir:  # xxx/newdir/. exists if xxx/newdir exists
            return
    try:
        mkdir(name, mode)
    except OSError as e:
        # be happy if someone already created the path
        if e.errno != errno.EEXIST:
            raise

    chmod(name, mode)


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def blake2b(fname):
    hash_blake2b = hashlib.blake2b()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_blake2b.update(chunk)
    return hash_blake2b.hexdigest()


def _get_hashing_algorithm(hash_algorithm):
    # check hash algorithm
    algorithm_list = hashlib.algorithms_available
    if hash_algorithm not in algorithm_list:
        raise WazuhError(1723, "Available algorithms are {0}.".format(', '.join(algorithm_list)))

    return hashlib.new(hash_algorithm)


def get_hash(filename, hash_algorithm='md5', return_hex=True):
    hashing = _get_hashing_algorithm(hash_algorithm)

    try:
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hashing.update(chunk)
    except (IOError, OSError):
        return None

    return hashing.hexdigest() if return_hex else hashing.digest()


def get_hash_str(my_str, hash_algorithm='md5'):
    hashing = _get_hashing_algorithm(hash_algorithm)
    hashing.update(my_str.encode())
    return hashing.hexdigest()


def get_fields_to_nest(fields, force_fields=[], split_character="_"):
    nest = {k: set(filter(lambda x: x != k, chain.from_iterable(g)))
            for k, g in groupby(map(lambda x: x.split(split_character), sorted(fields)),
                                key=lambda x: x[0])}
    nested = filter(lambda x: len(x[1]) > 1 or x[0] in force_fields, nest.items())
    nested = [(field, {(subfield, split_character.join([field, subfield])) for subfield in subfields}) for
              field, subfields in nested]
    non_nested = set(filter(lambda x: x.split(split_character)[0] not in map(operator.itemgetter(0), nested), fields))
    return nested, non_nested


def plain_dict_to_nested_dict(data, nested=None, non_nested=None, force_fields=[], split_character='_'):
    """
    Turns an input dictionary with "nested" fields in form
                field_subfield
    into a real nested dictionary in form
                field {subfield}
    For example, the following input dictionary
    data = {
       "ram_free": "1669524",
       "board_serial": "BSS-0123456789",
       "cpu_name": "Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz",
       "cpu_cores": "4",
       "ram_total": "2045956",
       "cpu_mhz": "2394.464"
    }
    will output this way:
    data = {
      "ram": {
         "total": "2045956",
         "free": "1669524"
      },
      "cpu": {
         "cores": "4",
         "mhz": "2394.464",
         "name": "Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz"
      },
      "board_serial": "BSS-0123456789"
    }
    :param data: dictionary to nest
    :param nested: fields to nest
    :param force_fields: fields to force nesting in
    """
    # separate fields and subfields:
    # nested = {'board': ['serial'], 'cpu': ['cores', 'mhz', 'name'], 'ram': ['free', 'total']}
    nested = {k: list(filter(lambda x: x != k, chain.from_iterable(g)))
              for k, g in groupby(map(lambda x: x.split(split_character), sorted(data.keys())),
                                  key=lambda x: x[0])}

    # create a nested dictionary with those fields that have subfields
    # (board_serial won't be added because it only has one subfield)
    #  nested_dict = {
    #       'cpu': {
    #           'cores': '4',
    #           'mhz': '2394.464',
    #           'name': 'Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz'
    #       },
    #       'ram': {
    #           'free': '1669524',
    #           'total': '2045956'
    #       }
    #    }
    nested_dict = {f: {sf: data['{0}{2}{1}'.format(f, sf, split_character)] for sf in sfl} for f, sfl
                   in nested.items() if len(sfl) > 1 or f in force_fields}

    # create a dictionary with the non nested fields
    # non_nested_dict = {'board_serial': 'BSS-0123456789'}
    non_nested_dict = {f: data[f] for f in data.keys() if f.split(split_character)[0]
                       not in nested_dict.keys()}

    # append both dictionaries
    nested_dict.update(non_nested_dict)

    return nested_dict


def check_remote_commands(data: str):
    """Check if remote commands are allowed. If not, it will check if the found command is in the list of exceptions.

    Parameters
    ----------
    data : str
        Configuration file
    """
    blocked_configurations = configuration.api_conf['upload_configuration']

    def check_section(command_regex, section, split_section):
        try:
            for line in command_regex.findall(data)[0].split(split_section):
                command_matches = re.match(r".*<(command|full_command)>(.*)</(command|full_command)>.*",
                                           line, flags=re.MULTILINE | re.DOTALL)
                if command_matches and \
                        (line.count('<command>') > 1 or
                         command_matches.group(2) not in
                         blocked_configurations['remote_commands'][section].get('exceptions', [])):
                    raise WazuhError(1124)
        except IndexError:
            pass

    if not blocked_configurations['remote_commands']['localfile']['allow']:
        command_section = re.compile(r"<localfile>(.*?)</localfile>", flags=re.MULTILINE | re.DOTALL)
        check_section(command_section, section='localfile', split_section='</localfile>')

    if not blocked_configurations['remote_commands']['wodle_command']['allow']:
        command_section = re.compile(r"<wodle name=\"command\">(.*?)</wodle>", flags=re.MULTILINE | re.DOTALL)
        check_section(command_section, section='wodle_command', split_section='<wodle name=\"command\">')


def check_wazuh_limits_unchanged(new_conf, original_conf):
    """Check if Wazuh limits remain unchanged.

    Parameters
    ----------
    new_conf : str
        New configuration file.
    original_conf : str
        Original configuration file.

    Raises
    -------
    WazuhError(1127)
        Raised if one of the protected limits is modified in the configuration to upload.
    """

    def xml_to_dict(conf, section_name):
        """Convert XML to list of dictionaries.

        Parameters
        ----------
        conf : str
            XML configuration file.
        section_name : str
            Name of the section to extract from the configuration file.

        Returns
        -------
        matched_configurations : list
            Dictionaries with the configuration.
        """
        matched_configurations = []

        for str_conf in re.findall(r'<ossec_config>.*?</ossec_config>', conf, re.MULTILINE | re.DOTALL | re.IGNORECASE):
            ossec_config_section = fromstring(str_conf)
            for global_section in ossec_config_section.iter('global'):
                for limits_section in global_section.iter('limits'):
                    for section in limits_section.iter(section_name):
                        section_dict = {section.tag: {}}
                        for config in section:
                            section_dict[section.tag].update({config.tag: {'attrib': config.attrib,
                                                                           'value': config.text.strip()}})
                        matched_configurations.append(section_dict)

        return matched_configurations

    limits_configuration = configuration.api_conf['upload_configuration']['limits']
    for disabled_limit in [conf for conf, allowed in limits_configuration.items() if not allowed['allow']]:
        new_limits = xml_to_dict(new_conf, disabled_limit)
        original_limits = xml_to_dict(original_conf, disabled_limit)

        if len(new_limits) != len(original_limits) or any(x != y for x, y in zip(new_limits, original_limits)):
            raise WazuhError(1127, extra_message=f"global > limits > {disabled_limit}")


def check_agents_allow_higher_versions(data: str):
    """Check if higher version agents are allowed.

    Parameters
    ----------
    data : str
        Configuration file content.
    """
    blocked_configurations = configuration.api_conf['upload_configuration']

    def check_section(agents_regex, split_section):
        try:
            for line in agents_regex.findall(data)[0].split(split_section):
                tag_matches = re.match(r".*<allow_higher_versions>(.*)</allow_higher_versions>.*",
                                            line, flags=re.MULTILINE | re.DOTALL)
                if tag_matches and (tag_matches.group(1) == 'yes'):
                    raise WazuhError(1129)
        except IndexError:
            pass

    if not blocked_configurations['agents']['allow_higher_versions']['allow']:
        remote_section = re.compile(r"<remote>(.*)</remote>", flags=re.MULTILINE | re.DOTALL)
        check_section(remote_section, split_section='</remote>')

        auth_section = re.compile(r"<auth>(.*)</auth>", flags=re.MULTILINE | re.DOTALL)
        check_section(auth_section, split_section='</auth>')


def check_indexer(new_conf: str, original_conf: str):
    """Check if modifying the indexer configuration is allowed.

    Parameters
    ----------
    new_conf : str
        New configuration file.
    original_conf : str
        Original configuration file.

    Raises
    -------
    WazuhError(1127)
        Raised if the indexer section is modified in the configuration to upload.
    """

    def update_dict(section_dict: dict, section):
        """Updates a dictionary with the values of a section recursively.

        Parameters
        ----------
        section_dict : dict
            Section dictionary.
        section : Element
            XML section to get the values from.
        """
        for value in section:
            if value.text is None:
                # The value contains more tags, iterate over them
                update_dict(section_dict, value)
                return

            section_dict.update({value.tag: {'attrib': value.attrib, 'value': value.text.strip()}})

    def xml_to_dict(conf: str) -> list:
        """Convert XML to a list of dictionaries.

        Parameters
        ----------
        conf : str
            XML configuration file.

        Returns
        -------
        matched_configurations : list
            Dictionaries with the configuration.
        """
        matched_configurations = []

        for str_conf in re.findall(r'<indexer>.*?</indexer>', conf, re.MULTILINE | re.DOTALL | re.IGNORECASE):
            indexer_section = fromstring(str_conf)

            for section in indexer_section.iter():
                section_dict = {section.tag: {}}
                update_dict(section_dict[section.tag], section)
                matched_configurations.append(section_dict)

        return matched_configurations

    upload_configuration = configuration.api_conf['upload_configuration']

    if not upload_configuration['indexer']['allow']:
        new_indexer = xml_to_dict(new_conf)
        original_indexer = xml_to_dict(original_conf)
        if len(new_indexer) != len(original_indexer) or any(x != y for x, y in zip(new_indexer, original_indexer)):
            raise WazuhError(1127, extra_message='indexer')


def check_virustotal_integration(new_conf: str):
    """Check if the configuration VirusTotal API Key corresponds to Public or Premium API.

    Parameters
    ----------
    new_conf : str
        New configuration file.

    Raises
    -------
    WazuhError(1127)
        Raised if the integrations section is modified in the configuration to upload.
    """

    def obtain_vt_api_keys(conf: str) -> list[str]:
        """Obtain Virus Total API keys from the configuration.

        Parameters
        ----------
        conf : str
            XML configuration file.

        Returns
        -------
        keys: list[str]
            Virus Total API keys.
        """
        keys = []
        for str_conf in re.findall(r'<integration>.*?</integration>', conf, re.MULTILINE | re.DOTALL | re.IGNORECASE):
            integrations_section = fromstring(str_conf)
            for name_section in integrations_section.iter('name'):
                if name_section.text.strip() == 'virustotal':
                    for api_key_section in integrations_section.iter('api_key'):
                        keys.append(api_key_section.text.strip())
        return keys

    blocked_configurations = configuration.api_conf['upload_configuration']['integrations']['virustotal']

    if not blocked_configurations['public_key']['allow']:
        minimum_quota = blocked_configurations['public_key']['minimum_quota']
        api_keys = obtain_vt_api_keys(new_conf)
        for api_key in api_keys:
            headers = {'x-apikey': f'{api_key}'}
            url = f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas"
            try:
                virustotal_response = get(url=url, headers=headers, timeout=10).json()
                response_minimum_quota = virustotal_response["data"]["api_requests_hourly"]["user"]["allowed"]
            except (exceptions.RequestException, KeyError) as e:
                extra_msg = "Unexpected VirusTotal response" if type(e) == KeyError else str(e)
                raise WazuhError(1131, extra_message=f'{extra_msg}')
            if response_minimum_quota == minimum_quota:
                raise WazuhError(1130, extra_message='integrations > virustotal')


def load_wazuh_xml(xml_path, data=None):
    if not data:
        with open(xml_path) as f:
            try:
                data = f.read()
            except Exception as e:
                raise WazuhError(1113, extra_message=str(e))

    # -- characters are not allowed in XML comments
    xml_comment = re.compile(r"(<!--(.*?)-->)", flags=re.MULTILINE | re.DOTALL)
    for comment in xml_comment.finditer(data):
        good_comment = comment.group(2).replace('--', '..')
        data = data.replace(comment.group(2), good_comment)

    # Replace &lt; and &gt; currently present in the config
    data = data.replace('&lt;', '_custom_amp_lt_').replace('&gt;', '_custom_amp_gt_')

    custom_entities = {
        'backslash': '\\'
    }

    # replace every custom entity
    for character, replacement in custom_entities.items():
        data = re.sub(replacement.replace('\\', '\\\\'), f'&{character};', data)

    # < characters should be escaped as &lt; unless < is starting a <tag> or a comment
    data = re.sub(r"<(?!/?\w+.+>|!--)", "&lt;", data)

    # replace \< by &lt, only outside xml tags;
    data = re.sub(r'^&backslash;<(.*[^>])$', r'&backslash;&lt;\g<1>', data)

    # replace \> by &gt;
    data = re.sub(r'&backslash;>', '&backslash;&gt;', data)

    # default entities
    default_entities = ['amp', 'lt', 'gt', 'apos', 'quot']

    # & characters should be escaped if they don't represent an &entity;
    data = re.sub(f"&(?!({'|'.join(default_entities + list(custom_entities))});)", "&amp;", data)

    entities = '<!DOCTYPE xmlfile [\n' + \
               '\n'.join([f'<!ENTITY {name} "{value}">' for name, value in custom_entities.items()]) + \
               '\n]>\n'

    return fromstring(f"{entities}<root_tag>{data}</root_tag>", forbid_entities=False)


class WazuhVersion:

    def __init__(self, version):

        pattern = r"(?:Wazuh )?v?(\d+)\.(\d+)\.(\d+)\-?(alpha|beta|rc)?(\d*)"
        m = re.match(pattern, version)

        if m:
            self.__mayor = int(m.group(1))
            self.__minor = int(m.group(2))
            self.__patch = int(m.group(3))
            self.__dev = m.group(4)
            self.__dev_ver = m.group(5)
        else:
            raise ValueError("Invalid version format.")

    def to_array(self):
        array = [str(self.__mayor)]
        array.extend(str(self.__minor))
        array.extend(str(self.__patch))
        if self.__dev:
            array.append(self.__dev)
        if self.__dev_ver:
            array.append(self.__dev_ver)
        return array

    def __to_string(self):
        ver_string = "{0}.{1}.{2}".format(self.__mayor, self.__minor, self.__patch)
        if self.__dev:
            ver_string = "{0}-{1}{2}".format(ver_string, self.__dev, self.__dev_ver)
        return ver_string

    def __str__(self):
        return self.__to_string()

    def __eq__(self, new_version):
        return (self.__to_string() == new_version.__to_string())

    def __ne__(self, new_version):
        return (self.__to_string() != new_version.__to_string())

    def __ge__(self, new_version):
        if self.__mayor < new_version.__mayor:
            return False
        elif self.__mayor == new_version.__mayor:
            if self.__minor < new_version.__minor:
                return False
            elif self.__minor == new_version.__minor:
                if self.__patch < new_version.__patch:
                    return False
                elif self.__patch == new_version.__patch:
                    if (self.__dev) and not (new_version.__dev):
                        return False
                    elif (self.__dev) and (new_version.__dev):
                        if ord(self.__dev[0]) < ord(new_version.__dev[0]):
                            return False
                        elif ord(self.__dev[0]) == ord(new_version.__dev[0]) and self.__dev_ver < new_version.__dev_ver:
                            return False

        return True

    def __lt__(self, new_version):
        return not (self >= new_version)

    def __gt__(self, new_version):
        return (self >= new_version and self != new_version)

    def __le__(self, new_version):
        return (not (self > new_version) or self == new_version)


def get_timeframe_in_seconds(timeframe: str) -> int:
    """Get number of seconds from a timeframe.

    Parameters
    ----------
    timeframe : str
        Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s".

    Raises
    ------
    WazuhError(1411)
        The timeframe value is not valid.

    Returns
    -------
    int
        Time in seconds.
    """
    if not timeframe.isdigit():
        if 'h' not in timeframe and 'd' not in timeframe and 'm' not in timeframe and 's' not in timeframe:
            raise WazuhError(1411, timeframe)

        regex, seconds = re.compile(r'(\d+)(\w)'), 0
        time_equivalence_seconds = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
        for time, unit in regex.findall(timeframe):
            # it's not necessarry to check whether the unit is in the dictionary, because it's been validated before.
            seconds += int(time) * time_equivalence_seconds[unit]
    else:
        seconds = int(timeframe)

    return seconds


def filter_array_by_query(q: str, input_array: typing.List) -> typing.List:
    """Filter a list of dictionaries by 'q' parameter, like as a SQL query.

    Parameters
    ----------
    input_array : list
        List to be filtered.
    q : str
        query for filtering a list.

    Returns
    -------
    list
        List with processed query.
    """

    def check_date_format(element: str) -> typing.Union[str, datetime]:
        """Check if a given field is a date. If so, transform the date to the standard API format (ISO 8601).
        If not, return the field.

        Parameters
        ----------
        element : str
            Item to check.

        Returns
        -------
        str or datetime
            In case of a date, return the element after its conversion. Otherwise it return the element.
        """
        date_patterns = ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%fZ']

        for pattern in date_patterns:
            try:
                return get_utc_strptime(element, pattern)
            except ValueError:
                pass

        return element

    def check_clause(value1: typing.Union[str, int], op: str, value2: str) -> bool:
        """Check an operation between value1 and value2. 'value1' could be an integer, it is necessary cast value2 to
        integer if this happens

        Parameters
        ----------
        value1 : str or int
            First value of the operation.
        op : str
            Operation to be done.
        value2 : str
            Second value of the operation.

        Returns
        -------
        bool
            True if operation is satisfied, False otherwise.
        """
        operators = {'=': operator.eq,
                     '!=': operator.ne,
                     '<': operator.lt,
                     '>': operator.gt}
        value1 = [value1] if not isinstance(value1, list) else value1
        for val in value1:
            if op == '~':
                # value1 should be str if operator is '~'
                val = str(val) if type(val) == int else val
                if value2 in val:
                    return True
            else:
                # cast value2 to integer if value1 is integer
                value2 = check_date_format(value2)
                if type(value2) == datetime:
                    val = check_date_format(val)
                value2 = int(value2) if type(val) == int else value2
                if operators[op](val, value2):
                    return True

        return False

    def get_match_candidates(iterable: typing.Union[dict, list], key_list: list, candidates: list) -> bool:
        """Get the match candidates following a list of keys.

        Parameters
        ----------
        iterable : dict or list
            Iterable object to be iterated over.
        key_list : list
            List of keys.
        candidates : list
            Empty list that will be filled

        Raises
        ------
        WazuhError(1407)
            Parameter q is not valid.

        Returns
        -------
        bool
            True if there is one match at least. False otherwise.
        """
        for index, key in enumerate(key_list):
            if isinstance(iterable, list):
                candidate_list = list()
                for element in list(iterable):
                    candidate_list.append(get_match_candidates(element, key_list[index:], candidates))
                if True in candidate_list:
                    return True
                else:
                    return False
            else:
                if key in iterable:
                    iterable = iterable[key]
                else:
                    return False
        else:
            candidates.append(iterable)
            return True

    # compile regular expression only one time when function is called
    # get elements in a clause
    operators = ['=', '!=', '<', '>', '~']
    re_get_elements = re.compile(
        r"\(?" +
        # Field name: name of the field to look on DB.
        r"([\w]+)" +
        # New capturing group for text after the first dot.
        r"\.?([\w.]*)?" +
        # Operator: looks for '=', '!=', '<', '>' or '~'.
        rf"([{''.join(operators)}]{{1,2}})" +
        # Value: A string.
        r"((?:(?:\((?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}]*)\))*"
        r"(?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}]+)"
        r"(?:\((?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}]*)\))*)+)" +
        r"\)?"
    )

    # get a list with OR clauses
    or_clauses = q.split(',')
    output_array = []
    # process elements of input_array
    for elem in input_array:
        # if an element matches an OR clause, it will be added to output
        for or_clause in or_clauses:
            # all AND clauses should match for adding an element to output
            and_clauses = or_clause.split(';')
            match = True  # flag for checking clauses
            for and_clause in and_clauses:
                # get elements in a clause
                try:
                    field_name, field_subnames, op, value = re_get_elements.match(and_clause).groups()
                except AttributeError:
                    raise WazuhError(1407, extra_message=f"Parameter 'q' is not valid: '{and_clause}'")

                # check if a clause is satisfied
                match_candidates = list()
                if field_subnames and field_name in elem and \
                        get_match_candidates(deepcopy(elem[field_name]), field_subnames.split('.'), match_candidates):
                    if any([check_clause(candidate, op, value) for candidate in match_candidates if candidate]):
                        continue
                else:
                    if field_name in elem and check_clause(elem[field_name], op, value):
                        continue
                match = False
                break

            # if match = True, add element to output and break the loop
            if match:
                output_array.append(elem)
                break
    return output_array


class AbstractDatabaseBackend:
    """
    This class describes an abstract database backend that executes database queries.
    """

    def __init__(self):
        self.conn = self.connect_to_db()

    def connect_to_db(self):
        raise NotImplementedError

    def execute(self, query, request, count=False):
        raise NotImplementedError


class WazuhDBBackend(AbstractDatabaseBackend):
    """
    This class describes a wazuh db backend that executes database queries.
    """

    def __init__(self, agent_id=None, query_format='agent', request_slice=500):
        if query_format == 'agent' and not path.exists(path.join(common.WDB_PATH, f"{agent_id}.db")):
            raise WazuhError(2007, extra_message=f"There is no database for agent {agent_id}. "
                                                 "Please check if the agent has connected to the manager")

        self.agent_id = agent_id
        self.query_format = query_format
        self.request_slice = request_slice

        super().__init__()

    def connect_to_db(self):
        return WazuhDBConnection(request_slice=self.request_slice)

    def close_connection(self):
        self.conn.close()

    def _substitute_params(self, query, request):
        """
        Substitute request parameters in query. This is only necessary when the backend is wdb. Sqlite substitutes
        parameters by itself.
        """
        for k, v in request.items():
            if isinstance(v, list):
                values = list()
                for element in v:
                    if isinstance(element, (int, float)) or (isinstance(element, str) and element.isnumeric()):
                        values.append(element)
                    else:
                        values.append(f"'{element}'")
                value = f"{','.join(values)}"
            elif isinstance(v, (int, float)):
                value = f"{v}"
            elif isinstance(v, str):
                value = f"'{v}'"
            else:
                raise TypeError(f'Invalid type for request parameters: {type(v)}')
            # Escape backslash to avoid re error
            value = value.replace('\\', '\\\\')
            query = re.sub(r':\b' + re.escape(str(k)) + r'\b', value, query)
        return query

    def _render_query(self, query):
        """Render query attending the format."""
        if self.query_format == 'mitre':
            return f'mitre sql {query}'
        elif self.query_format == 'task':
            return f'task sql {query}'
        elif self.query_format == 'global':
            return f'global sql {query}'
        else:
            return f'agent {self.agent_id} sql {query}'

    def execute(self, query, request, count=False):
        """Execute SQL query through WazuhDB socket."""
        query = self._substitute_params(query, request)
        return self.conn.execute(query=self._render_query(query), count=count)


class WazuhDBQuery(object):
    """This class describes a database query for wazuh."""

    def __init__(self, offset: int, limit: int, table: str, sort: dict, search: dict, select: list, query: str,
                 fields: dict, default_sort_field: str, count: bool, get_data: bool, backend: str,
                 default_sort_order: str = 'ASC', filters: dict = {}, min_select_fields: set = set(),
                 date_fields: set = set(), extra_fields=set(), distinct: bool = False, rbac_negate: bool = True):
        """Wazuh DB Query constructor.

        Parameters
        ----------
        offset : int
            First item to return.
        limit : int
            Maximum number of items to return.
        table : str
            Table to do the query.
        sort : dict
            Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        select : list
            Select fields to return. Format: ["field1","field2"].
        filters : dict
            Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        query : str
            Query to filter in database. Format: field operator value.
        fields : dict
            All available fields.
        search : dict
            Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        default_sort_field : str
            By default, return elements sorted by this field.
        default_sort_order : str
            By default, return elements sorted in this order
        min_select_fields : set
            Fields that must be always be selected because they're necessary to compute other fields.
        date_fields : set
            Database fields that represent a date.
        extra_fields : set
            Extra fields.
        count : bool
            Whether to compute totalItems or not.
        get_data : bool
            Whether to return data or not.
        distinct : bool
            Look for distinct values.
        rbac_negate : bool
            Whether to use IN or NOT IN on RBAC resources.
        backend : str
            Database engine to use. Possible options are 'wdb' and 'sqlite3'.
        """
        self.offset = offset
        self.limit = limit
        self.table = table
        self.sort = sort
        self.search = search
        self.select = None if not select else select.copy()
        self.fields = fields.copy()
        self.distinct = distinct
        self.query = self._default_query()
        self.request = {}
        self.default_sort_field = default_sort_field
        self.default_sort_order = default_sort_order
        self.query_filters = []
        self.count = count
        self.data = get_data
        self.total_items = 0
        # Do not include any fields when we are looking for distinct values
        self.min_select_fields = set() if distinct else min_select_fields
        self.query_operators = {"=": "=", "!=": "!=", "<": "<", ">": ">", "~": 'LIKE'}
        self.query_separators = {',': 'OR', ';': 'AND', '': ''}
        self.special_characters = "\'\""
        self.wildcard_equal_fields = set()
        # To correctly turn a query into SQL, a regex is used. This regex will extract all necessary information:
        # For example, the following regex -> (name!=wazuh;id>5),group=webserver <- would return 3 different matches:
        #   (name != wazuh ;
        #    id   > 5      ),
        #    group=webserver
        self.query_regex = re.compile(
            # One or more ( characters.
            r"(\(+)?" +
            # Field name: name of the field to look on DB.
            r"([\w.]+)" +
            # Operator: looks for '=', '!=', '<', '>' or '~'.
            rf"([{''.join(self.query_operators.keys())}]{{1,2}})" +
            # Value: A string.
            r"((?:(?:\((?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}$]*)\))*"
            r"(?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}$]+)"
            r"(?:\((?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}$]*)\))*)+)"
            # One or more ) characters.
            r"(\)+)?" +
            # Separator: looks for ';', ',' or nothing.
            rf"([{''.join(self.query_separators.keys())}])?"
        )
        self.date_fields = date_fields
        self.extra_fields = extra_fields
        self.q = query
        self.legacy_filters = filters.copy() if filters else filters
        self.inverse_fields = {v: k for k, v in self.fields.items()}
        self.backend = backend
        self.rbac_negate = rbac_negate

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        isinstance(self.backend, WazuhDBBackend) and self.backend.close_connection()

    def _clean_filter(self, query_filter):
        if isinstance(query_filter['value'], str):
            try:
                query_filter['value'] = json.dumps(json.loads(query_filter['value']), separators=(',', ':'))
            except ValueError:
                pass

        # Replace special characters with wildcards
        for sp_char in self.special_characters:
            if isinstance(query_filter['value'], str) and sp_char in query_filter['value']:
                if query_filter['operator'] != 'LIKE':
                    # If original operator was not LIKE, do not append % at the beginning and end of the string
                    self.wildcard_equal_fields.add(query_filter['field'])

                query_filter['value'] = query_filter['value'].replace(sp_char, '_')
                query_filter['operator'] = 'LIKE'

    def _add_limit_to_query(self):
        if self.limit:
            if self.limit > common.MAXIMUM_DATABASE_LIMIT:
                raise WazuhError(1405, extra_message=str(self.limit))
            self.query += ' LIMIT :limit OFFSET :offset'
            self.request['offset'] = self.offset
            self.request['limit'] = self.limit
        elif self.limit == 0:  # 0 is not a valid limit
            raise WazuhError(1406)

    def _sort_query(self, field):
        return '{} {}'.format(self.fields[field], self.sort['order'])

    def _add_sort_to_query(self):
        if self.sort:
            if self.sort['fields']:
                sort_fields, allowed_sort_fields = self.sort['fields'], set(self.fields.keys())
                # Check every element in sort['fields'] is in allowed_sort_fields
                if not set(sort_fields).issubset(allowed_sort_fields):
                    raise WazuhError(1403, "Allowed sort fields: {}. Fields: {}".format(
                        sorted(allowed_sort_fields, key=str), ', '.join(set(sort_fields) - allowed_sort_fields)
                    ))
                self.query += ' ORDER BY ' + ','.join([self._sort_query(i) for i in sort_fields])
            else:
                self.query += ' ORDER BY {0} {1}'.format(self.default_sort_field, self.sort['order'])
        else:
            self.query += ' ORDER BY {0} {1}'.format(self.default_sort_field, self.default_sort_order)

    def _add_search_to_query(self):
        if self.search:
            self.query += " AND NOT" if bool(self.search['negation']) else ' AND'
            self.query += " (" + " OR ".join(
                f'({x.split(" as ")[0]} LIKE :search AND {x.split(" as ")[0]} IS NOT NULL)' for x in
                self.fields.values()) + ')'
            self.query = self.query.replace('WHERE  AND', 'WHERE')
            self.request['search'] = "%{0}%".format(re.sub(f"[{self.special_characters}]", '_', self.search['value']))

    def _parse_select_filter(self, select_fields):
        if select_fields:
            set_select_fields = set(select_fields)
            set_fields_keys = set(self.fields.keys()) - self.extra_fields

            # if select is empty, it will be a subset of any set
            if not set_select_fields or not set_select_fields.issubset(set_fields_keys):
                raise WazuhError(1724, "Allowed select fields: {0}. Fields {1}". \
                                 format(', '.join(self.fields.keys()),
                                        ', '.join(set_select_fields - set_fields_keys)))

            select_fields = set_select_fields
        else:
            select_fields = self.fields.keys()

        return select_fields

    def _add_select_to_query(self):
        self.select = self._parse_select_filter(self.select)

    def _parse_query(self):
        """A query has the following pattern: field operator value separator field operator value...

        An example of query: status=never_connected;name!=pepe
            * Field must be a database field (it must be contained in self.fields variable)
            * operator must be one of = != < >
            * value can be anything
            * Separator can be either ; for 'and' or , for 'or'.
        """
        if not self.query_regex.match(self.q):
            raise WazuhError(1407, self.q)

        level = 0
        for open_level, field, operator, value, close_level, separator in self.query_regex.findall(self.q):
            if field not in self.fields.keys():
                raise WazuhError(1408, "Available fields: {}. Field: {}".format(', '.join(self.fields), field))
            if operator not in self.query_operators:
                raise WazuhError(1409,
                                 "Valid operators: {}. Used operator: {}".format(', '.join(self.query_operators),
                                                                                 operator))

            if open_level:
                level += len(open_level)
            if close_level:
                level -= len(close_level)

            if not self._pass_filter(field, value):
                op_index = len(list(filter(lambda x: field in x['field'], self.query_filters)))
                self.query_filters.append({'value': None if value == "null" else value,
                                           'operator': self.query_operators[operator],
                                           'field': '{}${}'.format(field, op_index),
                                           'separator': self.query_separators[separator], 'level': level})

    def _parse_legacy_filters(self):
        """Parse legacy filters."""
        # some legacy filters can contain multiple values to filter separated by commas. That must split in a list.
        self.legacy_filters.get('older_than', None) == '0s' and self.legacy_filters.pop('older_than')
        legacy_filters_as_list = {
            name: value if isinstance(value, list) else [value] for name, value in self.legacy_filters.items()
        }
        # each filter is represented using a dictionary containing the following fields:
        #   * Value     -> Value to filter by
        #   * Field     -> Field to filter by. Since there can be multiple filters over the same field, a numeric ID
        #                  must be added to the field name.
        #   * Operator  -> Operator to use in the database query. In legacy filters the only available one is =.
        #   * Separator -> Logical operator used to join queries. In legacy filters, the AND operator is used when
        #                  different fields are filtered and the OR operator is used when filtering by the same field
        #                  multiple times.
        #   * Level     -> The level defines the number of parenthesis the query has. In legacy filters, no
        #                  parenthesis are used except when filtering over the same field.
        self.query_filters += [{'value': None if subvalue == "null" else subvalue,
                                'field': '{}${}'.format(name, i),
                                'operator': '=',
                                'separator': 'AND' if len(value) <= 1 or len(value) == i + 1 else 'OR',
                                'level': 0 if i == len(value) - 1 else 1}
                               for name, value in legacy_filters_as_list.items()
                               for i, subvalue in enumerate(value) if not self._pass_filter(name, subvalue)]

        if self.query_filters:
            # if only traditional filters have been defined, remove last AND from the query.
            self.query_filters[-1]['separator'] = '' if not self.q else 'AND'

    def _parse_filters(self):
        if self.legacy_filters:
            self._parse_legacy_filters()
        if self.q:
            self._parse_query()
        if self.search or self.query_filters:
            self.query += " WHERE " if 'WHERE' not in self.query else ' AND '

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name in self.date_fields and not isinstance(q_filter['value'], (int, float)):
            # Filter a date, only if it is a string and it can be derived into a date.
            # If it matches the same format as DB (timestamp integer), filter directly by value (next if cond).
            self._filter_date(q_filter, field_name)
        elif 'rbac' in field_name:
            self.query += f"{field_name.lstrip('rbac_')} {q_filter['operator']} (:{field_filter})"
            self.request[field_filter] = q_filter['value']
        else:
            if q_filter['value'] is not None:
                self.request[field_filter] = q_filter['value'] if field_name != "version" else re.sub(
                    r'([a-zA-Z])([v])', r'\1 \2', q_filter['value'])
                if q_filter['operator'] == 'LIKE' and q_filter['field'] not in self.wildcard_equal_fields:
                    self.request[field_filter] = "%{}%".format(self.request[field_filter])
                self.query += '{} {} :{}'.format(self.fields[field_name].split(' as ')[0], q_filter['operator'],
                                                 field_filter)
                if not field_filter.isdigit():
                    # filtering without being uppercase/lowercase sensitive
                    self.query += ' COLLATE NOCASE'
            else:
                self.query += '{} IS null'.format(self.fields[field_name])

    def _add_filters_to_query(self):
        self._parse_filters()

        curr_level = 0
        for q_filter in self.query_filters:
            self._clean_filter(q_filter)
            field_name = q_filter['field'].split('$', 1)[0]
            field_filter = q_filter['field'].replace('.', '_')
            level = q_filter['level']

            repeat_open = level + 1 - curr_level
            if level == 0 or repeat_open == 0:
                repeat_open = 1

            self.query += '(' * repeat_open

            self._process_filter(field_name, field_filter, q_filter)

            repeat_close = 1
            if curr_level > level:
                repeat_close += curr_level - level
            
            self.query += ')' * repeat_close
            self.query += ' {} '.format(q_filter['separator'])
            curr_level = level

        if self.distinct:
            self.query += ' WHERE ' if not self.q and 'WHERE' not in self.query else ' AND '
            self.query += ' AND '.join(
                ["{0} IS NOT null AND {0} != ''".format(self.fields[field]) for field in self.select])

    def _get_total_items(self):
        query_with_select_fields = self.query.format(','.join(map(lambda x: f"{self.fields[x]} as '{x}'",
                                                                  self.select | self.min_select_fields)))
        self.total_items = self.backend.execute(self._default_count_query().format(query_with_select_fields),
                                                self.request, True)

    def _execute_data_query(self):
        query_with_select_fields = self.query.format(','.join(map(lambda x: f"{self.fields[x]} as '{x}'",
                                                                  set(self.select) | self.min_select_fields)))

        self._data = self.backend.execute(query_with_select_fields, self.request)

    def _format_data_into_dictionary(self):
        return {'items': self._data, 'totalItems': self.total_items}

    def _filter_status(self, status_filter):
        raise NotImplementedError

    def _filter_date(self, date_filter, filter_db_name):
        # date_filter['value'] can be either a timeframe or a date in formats %Y-%m-%d, %Y-%m-%d %H:%M:%S or %Y-%m-%dT%H:%M:%SZ
        if date_filter['value'].isdigit() or re.match(r'\d+[dhms]', date_filter['value']):
            query_operator = '>' if date_filter['operator'] == '<' or date_filter['operator'] == '=' else '<'
            self.request[date_filter['field']] = get_timeframe_in_seconds(date_filter['value'])
            self.query += "{0} IS NOT NULL AND {0} {1}" \
                          " strftime('%s', 'now') - :{2} ".format(self.fields[filter_db_name],
                                                                  query_operator,
                                                                  date_filter['field'])
        elif re.match(r'\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}:\d{2}(.\d{1,6})?Z?)?', date_filter['value']):
            self.query += "{0} IS NOT NULL AND {0} {1} strftime('%s', :{2})".format(
                self.fields[filter_db_name], date_filter['operator'], date_filter['field'])
            self.request[date_filter['field']] = date_filter['value']
        else:
            raise WazuhError(1412, date_filter['value'])

    def general_run(self) -> dict:
        """Build the query and runs it on the database.

        Returns
        -------
        dict
            Dictionary with the formatted data.
        """
        self._add_select_to_query()
        self._add_filters_to_query()
        self._add_search_to_query()
        if self.count:
            self._get_total_items()
            if not self.data:
                return {'totalItems': self.total_items}
        self._add_sort_to_query()
        self._add_limit_to_query()
        if self.data:
            self._execute_data_query()
            return self._format_data_into_dictionary()

    def oversized_run(self) -> dict:
        """Method used when the size of the query exceeds the maximum available in the communication.
        Builds the query and runs it on the database.

        Returns
        -------
        dict
            Dictionary with the formatted data.

        Raises
        ------
        WazuhInternalError(1123)
            Error communicating with socket. Query too long.
        """
        self._add_select_to_query()
        original_select = self.select
        rbac_ids = set(self.legacy_filters.pop('rbac_ids', set()))
        self._add_filters_to_query()
        self._add_search_to_query()
        self._add_sort_to_query()

        resource = None
        final_ids = list()
        resources = list()
        if self.__class__.__name__ == 'WazuhDBQueryAgents':
            resource = 'id'
        elif self.__class__.__name__ == 'WazuhDBQueryGroups':
            resource = 'name'
        else:
            raise WazuhInternalError(1123)
        self.select = [resource]
        self._add_select_to_query()
        self._execute_data_query()
        try:
            resources = list(map(lambda d: str(d[resource]).zfill(3), self._data))
            maximum_value = min(self.limit, len(resources)) if self.limit is not None else len(resources)
            for item in resources:
                if self.rbac_negate:
                    if item.zfill(3) not in rbac_ids:
                        final_ids.append(item)
                else:
                    if item.zfill(3) in rbac_ids:
                        final_ids.append(item)
                if len(final_ids) >= maximum_value:
                    break
        except NameError:
            pass

        count = len(resources) - len(set(rbac_ids).intersection(set(resources))) if self.rbac_negate else \
            len(set(rbac_ids).intersection(set(resources)))

        self.select = original_select
        self.reset()
        self.legacy_filters['rbac_ids'] = final_ids
        original_count = self.count
        self.count = False
        result = self.general_run()
        if original_count:
            result['totalItems'] = count

        return result

    def run(self) -> dict:
        """Generic function that will redirect the information to the function that needs to be used for the specific
        case.

        Returns
        -------
        dict
            Dictionary with the formatted data.
        """
        if self.legacy_filters is None:
            return self.general_run()

        rbac_ids = set(self.legacy_filters.get('rbac_ids', set()))
        return self.general_run() if len(','.join(rbac_ids)) < common.MAX_QUERY_FILTERS_RESERVED_SIZE else \
            self.oversized_run()

    def reset(self):
        """Reset query to its initial value. Useful when doing several requests to the same DB."""
        self.query = self._default_query()
        self.query_filters = []
        self.select -= self.extra_fields

    def _default_query(self):
        """Get default query.

        Returns
        -------
        str
            The default query.
        """
        return "SELECT {0} FROM " + self.table if not self.distinct else "SELECT DISTINCT {0} FROM " + self.table

    def _default_count_query(self):
        return "SELECT COUNT(*) FROM ({0})"

    @staticmethod
    def _pass_filter(field, value):
        # field is used by child classes containing a field that may have a value equal to 'all'
        return value == "all"


class WazuhDBQueryDistinct(WazuhDBQuery):
    """Retrieve unique values for a given field."""

    def _default_query(self):
        return "SELECT DISTINCT {0} FROM " + self.table

    def _default_count_query(self):
        return "COUNT (DISTINCT {0})".format(','.join(map(lambda x: self.fields[x], self.select)))

    def _add_filters_to_query(self):
        WazuhDBQuery._add_filters_to_query(self)
        self.query += ' WHERE ' if not self.q and 'WHERE' not in self.query else ' AND '
        self.query += ' AND '.join(
            ["{0} IS NOT null AND {0} != ''".format(self.fields[field]) for field in self.select])

    def _add_select_to_query(self):
        if len(self.select) > 1:
            raise WazuhError(1410)

        WazuhDBQuery._add_select_to_query(self)

    def _format_data_into_dictionary(self):
        self._data = [next(iter(x.values())) for x in self._data]
        return WazuhDBQuery._format_data_into_dictionary(self)


class WazuhDBQueryGroupBy(WazuhDBQuery):
    """Retrieve unique values for multiple fields using group by."""

    def __init__(self, filter_fields, *args, **kwargs):
        WazuhDBQuery.__init__(self, *args, **kwargs)
        self.filter_fields = filter_fields

    def _get_total_items(self):
        # take total items without grouping, and add the group by clause just after getting total items
        WazuhDBQuery._get_total_items(self)
        self.select.add('count')
        self.inverse_fields['COUNT(*)'] = 'count'
        self.fields['count'] = 'COUNT(*)'
        self.query += ' GROUP BY ' + ','.join(map(lambda x: self.fields[x], self.filter_fields['fields']))

    def _add_select_to_query(self):
        WazuhDBQuery._add_select_to_query(self)
        self.filter_fields = self._parse_select_filter(self.filter_fields)
        if not isinstance(self.filter_fields, dict):
            self.filter_fields = {
                'fields': set(self.filter_fields)
            }
        self.select = self.select & self.filter_fields['fields']




def add_dynamic_detail(detail: str, value: str, attribs: dict, details: dict):
    """Add a detail with attributes (i.e. regex with negate or type).

    Parameters
    ----------
    detail : str
        Name of the detail.
    value : str
        Detail value.
    attribs : dict
        Dictionary with the XML attributes.
    details : dict
        Dictionary with all the current details.
    """
    if detail in details:
        new_pattern = details[detail]['pattern'] + value
        details[detail].clear()
        details[detail]['pattern'] = new_pattern
    else:
        details[detail] = dict()
        details[detail]['pattern'] = value

    details[detail].update(attribs)


def validate_wazuh_xml(content: str, config_file: bool = False):
    """Validate Wazuh XML files (rules, decoders and ossec.conf)

    Parameters
    ----------
    content : str
        File content.
    config_file : bool
        Validate remote commands if True.

    Raises
    ------
    WazuhError(1113)
        XML syntax error.
    """
    # -- characters are not allowed in XML comments
    content = replace_in_comments(content, '--', '%wildcard%')

    # Create temporary file for parsing xml input
    try:
        # Beautify xml file and escape '&' character as it could come in some tag values unescaped
        xml = parseString(f'<root>{content}</root>'.replace('&', '&amp;'))
        # Remove first line (XML specification: <? xmlversion="1.0" ?>), <root> and </root> tags, and empty lines
        indent = '  '  # indent parameter for toprettyxml function
        pretty_xml = '\n'.join(filter(lambda x: x.strip(), xml.toprettyxml(indent=indent).split('\n')[2:-2])) + '\n'
        # Revert xml.dom replacings
        # (https://github.com/python/cpython/blob/8e0418688906206fe59bd26344320c0fc026849e/Lib/xml/dom/minidom.py#L305)
        pretty_xml = pretty_xml.replace("&amp;", "&").replace("&lt;", "<").replace("&quot;", "\"", ) \
            .replace("&gt;", ">").replace('&apos;', "'")
        # Delete two first spaces of each line
        final_xml = re.sub(fr'^{indent}', '', pretty_xml, flags=re.MULTILINE)
        final_xml = replace_in_comments(final_xml, '%wildcard%', '--')

        # Check if remote commands are allowed if it is a configuration file
        if config_file:
            check_remote_commands(final_xml)
            check_agents_allow_higher_versions(final_xml)
            check_virustotal_integration(final_xml)
            with open(common.OSSEC_CONF, 'r') as f:
                current_xml = f.read()
            check_indexer(final_xml, current_xml)
            check_wazuh_limits_unchanged(final_xml, current_xml)
        # Check xml format
        load_wazuh_xml(xml_path='', data=final_xml)
    except ExpatError:
        raise WazuhError(1113)
    except WazuhError as e:
        raise e
    except Exception as e:
        raise WazuhError(1113, str(e))


def upload_file(content: str, file_path: str, check_xml_formula_values: bool = True):
    """Upload files (rules, lists, decoders and ossec.conf).

    Parameters
    ----------
    content: str
        Content of the XML file.
    file_path: str
        Destination of the new XML file.
    check_xml_formula_values: bool
        Check formula values in the resulting XML if true.

    Raises
    ------
    WazuhInternalError(1005)
        Error reading file.
    WazuhInternalError(1016)
        Error moving file.
    WazuhError(1006)
        Permision error accessing File or Directory.

    Returns
    -------
    WazuhResult
        Confirmation message.
    """

    def escape_formula_values(xml_string):
        """Prepend with a single quote possible formula injections."""
        formula_characters = ('=', '+', '-', '@')
        et = fromstring(f'<root>{xml_string}</root>')
        full_preprend, beginning_preprend = list(), list()
        for node in et.iter():
            if node.tag and node.tag.startswith(formula_characters):
                full_preprend.append(node.tag)
            if node.text and node.text.startswith(formula_characters) and ("'" in node.text or '"' in node.text):
                beginning_preprend.append(node.text)

        for text in full_preprend:
            xml_string = re.sub(f'<{re.escape(text)}>', f"<'{text}'>", xml_string)
            xml_string = re.sub(f'</{re.escape(text)}>', f"</'{text}'>", xml_string)

        for text in beginning_preprend:
            xml_string = re.sub(f'>{re.escape(text)}<', f">'{text}<", xml_string)

        return xml_string

    # Path of temporary files for parsing xml input
    handle, tmp_file_path = tempfile.mkstemp(prefix='api_tmp_file_', suffix='.tmp', dir=common.OSSEC_TMP_PATH)
    try:
        with open(handle, 'w') as tmp_file:
            final_file = escape_formula_values(content) if check_xml_formula_values else content
            tmp_file.write(final_file)
        chmod(tmp_file_path, 0o660)
    except IOError as exc:
        raise WazuhInternalError(1005) from exc

    # Move temporary file to group folder
    try:
        new_conf_path = path.join(common.WAZUH_PATH, file_path)
        safe_move(tmp_file_path, new_conf_path, ownership=(common.wazuh_uid(), common.wazuh_gid()), permissions=0o660)
    except PermissionError as exc:
        raise WazuhError(1006) from exc
    except Error as exc:
        raise WazuhInternalError(1016) from exc

    return results.WazuhResult({'message': 'File was successfully updated'})


def delete_file_with_backup(backup_file: str, abs_path: str, delete_function: callable):
    """Try to delete a file doing a backup beforehand.

    Parameters
    ----------
    backup_file : str
        Name of the backup file.
    abs_path : str
        Absolute path of the file to delete.
    delete_function : callable
        Function that will be used to delete the file.

    Raises
    ------
    WazuhError(1019)
        If there is any `IOError` while doing the backup.
    """
    try:
        full_copy(abs_path, backup_file)
    except IOError:
        raise WazuhError(1019)
    delete_function(filename=path.basename(abs_path))


def replace_in_comments(original_content, to_be_replaced, replacement):
    xml_comment = re.compile(r"(<!--(.*?)-->)", flags=re.MULTILINE | re.DOTALL)
    for comment in xml_comment.finditer(original_content):
        good_comment = comment.group(2).replace(to_be_replaced, replacement)
        original_content = original_content.replace(comment.group(2), good_comment)
    return original_content


def to_relative_path(full_path: str, prefix: str = common.WAZUH_PATH) -> str:
    """Return a relative path from the Wazuh base directory.

    Parameters
    ----------
    full_path : str
        Absolute path.
    prefix : str, opt
        Prefix to strip from the absolute path. Default `common.WAZUH_PATH`

    Returns
    -------
    str
        Relative path to `full_path` from `prefix`.
    """
    return path.relpath(full_path, prefix)


def clear_temporary_caches():
    """Clear all saved temporary caches."""
    t_cache.clear()


def temporary_cache():
    """Apply cache depending on whether function has its `cache` parameter set to `True` or not.

    Returns
    -------
    Requested function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            apply_cache = kwargs.pop('cache', None)

            @cached(cache=t_cache)
            def f(*_args, **_kwargs):
                return func(*_args, **_kwargs)

            if apply_cache:
                return f(*args, **kwargs)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def full_copy(src: str, dst: str, follow_symlinks: bool = True) -> None:
    """Copy a file maintaining all metadata if possible.

    Parameters
    ----------
    src: str
        Source absolute path.
    dst: str
        Destination absolute path.
    follow_symlinks: bool
        Make `copy2` follow symbolic links. False otherwise.
    """
    file_stat = os.stat(src)
    copy2(src, dst, follow_symlinks=follow_symlinks)
    try:
        # copy2 does not always copy the correct ownership
        chown(dst, file_stat.st_uid, file_stat.st_gid)
    except PermissionError:
        # Tried to assign 'root' ownership without being root. Default API permissions will be applied
        pass


class Timeout:
    """Raise TimeoutError after n seconds."""

    def __init__(self, seconds, error_message=''):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal(SIGALRM, self.handle_timeout)
        alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        alarm(0)


def get_date_from_timestamp(timestamp: float) -> datetime:
    """Function to return the date in datetime format and UTC timezone.

    Parameters
    ----------
    timestamp: float
        The timestamp.

    Returns
    -------
    date: datetime
        The default date.
    """
    return datetime.utcfromtimestamp(timestamp).replace(tzinfo=timezone.utc)


def get_utc_now() -> datetime:
    """Function to return the current date.

    Returns
    -------
    date: datetime
        The current date.
    """
    return datetime.utcnow().replace(tzinfo=timezone.utc)


def get_utc_strptime(date: str, datetime_format: str) -> datetime:
    """Function to transform str to date.

    Parameters
    ----------
    date: str
        String to be transformed.
    datetime_format: str
        Datetime pattern.

    Returns
    -------
    date: datetime
        The current date.
    """
    return datetime.strptime(date, datetime_format).replace(tzinfo=timezone.utc)

def check_if_wazuh_agent_version(version_str: str) -> bool:
    """Check if the string has the expected wazuh agent version format.

    Parameters
    ----------
    version_str : str
        The wazuh version string.

    Returns
    -------
    bool
        True if the string has the expected wazuh version format.

    """
    if not isinstance(version_str, str):
        return False

    return bool(re.match(r'^Wazuh v(\d+)\.(\d+)\.(\d+)', version_str))


def parse_wazuh_agent_version(version_str: str) -> tuple:
    """Convert the string vX.Y.Z to a tuple of type (X, Y, Z).

    Parameters
    ----------
    version_str : str
        The wazuh version string.

    Returns
    -------
    tuple
        The tuple of the wazuh version string.
    """
    match = re.search(r'v(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(map(int, match.groups()))
    return 0, 0, 0
