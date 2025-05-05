# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import errno
import hashlib
import operator
import os
import re
import sys
import typing
from copy import deepcopy
from datetime import datetime, timezone
from functools import wraps
from os import chmod, chown, curdir, mkdir, path, rename, utime
from pathlib import Path
from shutil import copy2, move
from signal import SIGALRM, SIGKILL, alarm, signal

import psutil
import yaml
from cachetools import TTLCache, cached
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from wazuh.core import common
from wazuh.core.exception import WazuhError

# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str

# Temporary cache
t_cache = TTLCache(maxsize=4500, ttl=60)

GROUP_FILE_EXT = '.yml'


def create_wazuh_dir(dirpath: Path):
    """Create a directory if it doesn't exist and assign ownership.

    Parameters
    ----------
    dirpath : Path
        Directory to create.
    """
    if not dirpath.exists():
        dirpath.mkdir()
        chown(dirpath, common.wazuh_uid(), common.wazuh_gid())


def assign_wazuh_ownership(filepath: str):
    """Create a file if it doesn't exist and assign ownership.

    Parameters
    ----------
    filepath : str
        File to assign ownership.
    """
    if not os.path.isfile(filepath):
        f = open(filepath, 'w')
        f.close()
    if os.stat(filepath).st_gid != common.wazuh_gid() or os.stat(filepath).st_uid != common.wazuh_uid():
        os.chown(filepath, common.wazuh_uid(), common.wazuh_gid())


def clean_pid_files(daemon: str) -> None:
    """Clean the '.pid' files for a specified daemon and kill their process group.

    Parameters
    ----------
    daemon : str
        Daemon's name.
    """
    regex = rf'{daemon}[\w_]*-(\d+).pid'
    for pid_file in os.listdir(common.WAZUH_RUN):
        if match := re.match(regex, pid_file):
            try:
                pid = int(match.group(1))
                process = psutil.Process(pid)
                command = (
                    process.cmdline()[-1] if process.status() != psutil.STATUS_ZOMBIE else daemon.replace('-', '_')
                )

                if daemon.replace('-', '_') in command:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, SIGKILL)
                    print(f'{daemon}: Orphan child process {pid} was terminated.')
                else:
                    print(f'{daemon}: Process {pid} does not belong to {daemon}, removing from {common.WAZUH_RUN}...')

            except (OSError, psutil.NoSuchProcess):
                print(f'{daemon}: Non existent process {pid}, removing from {common.WAZUH_RUN}...')
            finally:
                os.remove(path.join(common.WAZUH_RUN, pid_file))


def process_array(  # noqa: C901
    array: list,
    search_text: str = None,
    complementary_search: bool = False,
    search_in_fields: list = None,
    select: list = None,
    sort_by: list = None,
    sort_ascending: bool = True,
    allowed_sort_fields: list = None,
    offset: int = 0,
    limit: int = None,
    q: str = '',
    required_fields: list = None,
    allowed_select_fields: list = None,
    filters: dict = None,
    distinct: bool = False,
) -> dict:
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

    if sort_by == ['']:
        array = sort_array(array, sort_ascending=sort_ascending)
    elif sort_by:
        array = sort_array(
            array, sort_by=sort_by, sort_ascending=sort_ascending, allowed_sort_fields=allowed_sort_fields
        )

    if search_text:
        array = search_array(
            array, search_text=search_text, complementary_search=complementary_search, search_in_fields=search_in_fields
        )

    if q:
        array = filter_array_by_query(q, array)

    if select:
        # Do not force the inclusion of any fields when we are looking for distinct values
        required_fields = set() if distinct else required_fields
        array = select_array(
            array, select=select, required_fields=required_fields, allowed_select_fields=allowed_select_fields
        )

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
        return array[offset : offset + limit]


def sort_array(  # noqa: C901
    array: list, sort_by: list = None, sort_ascending: bool = True, allowed_sort_fields: list = None
) -> list:
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
            raise WazuhError(
                1403,
                extra_remediation='Allowed sort fields: {0}. Wrong fields: {1}'.format(
                    ', '.join(allowed_sort_fields), incorrect_fields
                ),
            )

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
                return sorted(
                    array,
                    key=lambda o: tuple(
                        o.get(a).lower() if type(o.get(a)) in (str, unicode) else o.get(a) for a in sort_by
                    ),
                    reverse=not sort_ascending,
                )
            except TypeError:
                items_with_missing_keys = list()
                copy_array = deepcopy(array)
                for item in array:
                    set(sort_by) & set(item.keys()) and items_with_missing_keys.append(
                        copy_array.pop(copy_array.index(item))
                    )

                sorted_array = sorted(
                    copy_array,
                    key=lambda o: tuple(
                        o.get(a).lower() if type(o.get(a)) in (str, unicode) else o.get(a) for a in sort_by
                    ),
                    reverse=not sort_ascending,
                )

                if not sort_ascending:
                    items_with_missing_keys.extend(sorted_array)
                    return items_with_missing_keys
                else:
                    sorted_array.extend(items_with_missing_keys)
                    return sorted_array

        else:
            return sorted(
                array,
                key=lambda o: tuple(
                    getattr(o, a).lower() if type(getattr(o, a)) in (str, unicode) else getattr(o, a) for a in sort_by
                ),
                reverse=not sort_ascending,
            )
    else:
        if type(array) is set or (type(array[0]) is not dict and "class 'wazuh" not in str(type(array[0]))):
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
        obj = o.to_dict()  # Agent...
    except Exception:
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


def search_array(
    array, search_text: str = None, complementary_search: bool = False, search_in_fields: list = None
) -> list:
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


def select_array(  # noqa: C901
    array: list, select: list = None, required_fields: set = None, allowed_select_fields: list = None
) -> list:
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
        raise WazuhError(1724, '{}'.format(', '.join(select_no_nested)))
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
            raise WazuhError(1724, '{}'.format(', '.join(select)))
        selected_fields.update({req_field: item[req_field] for req_field in required_fields})
        result_list.append(selected_fields)

    return result_list


def tail(filename: str, n: int = 20) -> list:
    """Return last 'n' lines of the file 'filename'.

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

        block_size = 1024
        f.seek(0, 2)
        block_end_byte = f.tell()
        lines_to_go = total_lines_wanted
        block_number = -1
        blocks = []  # blocks of size BLOCK_SIZE, in reverse order starting from the end of the file
        while lines_to_go > 0 and block_end_byte > 0:
            if block_end_byte - block_size > 0:
                # read the last block we haven't yet read
                f.seek(block_number * block_size, 2)
                blocks.append(f.read(block_size).decode('utf-8', errors='replace'))
            else:
                # file too small, start from beginning
                f.seek(0, 0)
                # only read what was not read
                blocks.append(f.read(block_end_byte).decode('utf-8', errors='replace'))
            lines_found = blocks[-1].count('\n')
            lines_to_go -= lines_found
            block_end_byte -= block_size
            block_number -= 1
        all_read_text = ''.join(reversed(blocks))

    return all_read_text.splitlines()[-total_lines_wanted:]


def safe_move(source: str, target: str, ownership: tuple = None, time: tuple = None, permissions: int = None):
    """Move a file even between filesystems.

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
    tmp_target = path.join(tmp_path, f'.{tmp_filename}.tmp')
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


def blake2b(file_path: str) -> str:
    """Get a file's content blake2b hash.

    Parameters
    ----------
    file_path : str
        File path.

    Returns
    -------
    str
        File content hash.
    """
    hash_blake2b = hashlib.blake2b()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_blake2b.update(chunk)
    return hash_blake2b.hexdigest()


def _get_hashing_algorithm(hash_algorithm):
    # check hash algorithm
    algorithm_list = hashlib.algorithms_available
    if hash_algorithm not in algorithm_list:
        raise WazuhError(1723, 'Available algorithms are {0}.'.format(', '.join(algorithm_list)))

    return hashlib.new(hash_algorithm)


def get_hash(filename, hash_algorithm='md5', return_hex=True) -> str | bytes:
    """Get a file's content hash.

    Parameters
    ----------
    filename : str
        File name.
    hash_algorithm : str
        Hash algorithm used. Default is md5.
    return_hex : bool
        Whether the returned string should be in hexadecimal. True by default.

    Returns
    -------
    str | bytes
        Digest value.
    """
    hashing = _get_hashing_algorithm(hash_algorithm)

    try:
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hashing.update(chunk)
    except (IOError, OSError):
        return None

    return hashing.hexdigest() if return_hex else hashing.digest()


def validate_wazuh_configuration(data: str):
    """Check that the Wazuh configuration provided is valid.

    Parameters
    ----------
    data : str
        Configuration content.
    """
    # TODO(#25121): Validate configuration


def load_wazuh_yaml(filepath: str, data: str = None) -> dict:
    """Load Wazuh YAML configuration files.

    Parameters
    ----------
    filepath : str
        File path.
    data : str
        YAML formatted string.

    Raises
    ------
    WazuhError(1006)
        File does not exist or lack of permissions.
    WazuhError(1132)
        Invalid YAML syntax.

    Returns
    -------
    dict
        Dictionary with the content.
    """
    if not data:
        try:
            with open(filepath) as f:
                data = f.read()
        except Exception as e:
            raise WazuhError(1006, extra_message=str(e))

    validate_wazuh_configuration(data)

    try:
        parsed_data = yaml.safe_load(data)
    except yaml.YAMLError as e:
        raise WazuhError(1132, extra_message=str(e))

    return parsed_data


def get_group_file_path(group_id: str) -> str:
    """Return the path to the group configuration file.

    Parameters
    ----------
    group_id : str
        Group ID.

    Returns
    -------
    str
        Group configuration file path.
    """
    return path.join(common.WAZUH_GROUPS, group_id + GROUP_FILE_EXT)


def filter_array_by_query(q: str, input_array: typing.List) -> typing.List:  # noqa: C901
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
        integer if this happens.

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
        operators = {'=': operator.eq, '!=': operator.ne, '<': operator.lt, '>': operator.gt}
        value1 = [value1] if not isinstance(value1, list) else value1
        for val in value1:
            if op == '~':
                # value1 should be str if operator is '~'
                val = str(val) if type(val) is int else val
                if value2 in val:
                    return True
            else:
                # cast value2 to integer if value1 is integer
                value2 = check_date_format(value2)
                if type(value2) is datetime:
                    val = check_date_format(val)
                value2 = int(value2) if type(val) is int else value2
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
        r'\(?'
        +
        # Field name: name of the field to look on DB.
        r'([\w]+)'
        +
        # New capturing group for text after the first dot.
        r'\.?([\w.]*)?'
        +
        # Operator: looks for '=', '!=', '<', '>' or '~'.
        rf'([{"".join(operators)}]{{1,2}})'
        +
        # Value: A string.
        r"((?:(?:\((?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}]*)\))*"
        r"(?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}]+)"
        r"(?:\((?:\[[\[\]\w _\-.,:?\\/'\"=@%<>{}]*]|[\[\]\w _\-.:?\\/'\"=@%<>{}]*)\))*)+)" + r'\)?'
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
                if (
                    field_subnames
                    and field_name in elem
                    and get_match_candidates(deepcopy(elem[field_name]), field_subnames.split('.'), match_candidates)
                ):
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
        """Raise timeout error."""
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal(SIGALRM, self.handle_timeout)
        alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        alarm(0)


def get_date_from_timestamp(timestamp: float) -> datetime:
    """Get the date in datetime format and UTC timezone.

    Parameters
    ----------
    timestamp: float
        The timestamp.

    Returns
    -------
    date: datetime
        The default date.
    """
    return datetime.fromtimestamp(timestamp, timezone.utc)


def get_utc_now() -> datetime:
    """Get the current date.

    Returns
    -------
    date: datetime
        The current date.
    """
    return datetime.now(timezone.utc)


def get_utc_strptime(date: str, datetime_format: str) -> datetime:
    """Transform str to date.

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


class KeystoreReader:
    """Class to read values from a keystore."""

    KEY_SIZE = 32
    IV_SIZE = 16
    KEY_VALUE_SEPARATOR = ':'

    def __init__(self, keystore_path: Path):
        self._data = keystore_path.read_bytes()
        self._cipher = self._get_cipher()
        self._keystore = self._decrypt_keystore()

    @staticmethod
    def _unpad(decrypted):
        return decrypted[: -ord(decrypted[len(decrypted) - 1 :])]

    def _get_cipher(self) -> Cipher:
        enc_key = self._data[: self.KEY_SIZE]
        iv = self._data[self.KEY_SIZE : self.KEY_SIZE + self.IV_SIZE]
        return Cipher(algorithms.AES(enc_key), modes.CBC(iv))

    def _decrypt_keystore(self) -> dict:
        value = self._data[self.KEY_SIZE + self.IV_SIZE :]
        decryptor = self._cipher.decryptor()
        decrypted = self._unpad(decryptor.update(value)).decode('utf-8')

        lines = decrypted.split('\n')
        lines.pop()
        kev_values = {}
        for line in lines:
            key_value = line.split(self.KEY_VALUE_SEPARATOR)
            key = key_value[0]
            value = key_value[1]
            kev_values[key] = value

        return kev_values

    def get(self, key: str, default: str | None) -> str | None:
        """Obtain the value that matches the given key.

        Parameters
        ----------
        key : str
            To obtain the value.
        default: str | None
            Value to return if key does not exists.

        Returns
        -------
        str | None
            The value if the key exists, else None.
        """
        return self._keystore.get(key, default)

    def __getitem__(self, attr):
        return self._keystore[attr]
