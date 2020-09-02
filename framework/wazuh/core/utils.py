# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import errno
import glob
import hashlib
import json
import operator
import re
import shutil
import stat
import sys
import typing
from datetime import datetime, timedelta
from itertools import groupby, chain
from os import chmod, chown, path, listdir, mkdir, curdir, rename, utime
from subprocess import CalledProcessError, check_output
from xml.etree.ElementTree import fromstring

from wazuh.core import common
from wazuh.core.database import Connection
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.wdb import WazuhDBConnection

# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str


def find_nth(string, substring, n):
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
        start = string.find(substring, start+len(substring))
        n -= 1
    return start


def previous_month(n=1):
    """Returns the first date of the previous n month.

    :param n: Number of months.
    :return: First date of the previous n month.
    """

    date = datetime.utcnow().replace(day=1)  # First day of current month

    for i in range(0, int(n)):
        date = (date - timedelta(days=1)).replace(day=1)  # (first_day - 1) = previous month

    return date.replace(hour=00, minute=00, second=00, microsecond=00)


def execute(command):
    """Executes a command. It is used to execute ossec commands.

    :param command: Command as list.
    :return: If output.error !=0 returns output.data, otherwise launches a WazuhException with output.error as error code and output.message as description.
    """
    try:
        output = check_output(command)
    except CalledProcessError as error:
        output = error.output
    except Exception as e:
        raise WazuhInternalError(1002, "{0}: {1}".format(command, e))  # Error executing command

    try:
        output_json = json.loads(output)
    except Exception as e:
        raise WazuhInternalError(1003, command)  # Command output not in json

    keys = output_json.keys()  # error and (data or message)
    if 'error' not in keys or ('data' not in keys and 'message' not in keys):
        raise WazuhInternalError(1004, command)  # Malformed command output

    if output_json['error'] != 0:
        raise WazuhInternalError(output_json['error'], output_json['message'], True)
    else:
        return output_json['data']


def process_array(array, search_text=None, complementary_search=False, search_in_fields=None, select=None, sort_by=None,
                  sort_ascending=True, allowed_sort_fields=None, offset=0, limit=None, q='', required_fields=None):
    """ Process a Wazuh framework data array

    :param array: Array to process
    :param search_text: Text to search and search type
    :param complementary_search: Perform a complementary search
    :param search_in_fields: Fields to search in
    :param select: Select fields to return
    :param sort_by: Fields to sort_by. Will sort the array directly if [''] is received
    :param sort_ascending: Sort order ascending or descending
    :param allowed_sort_fields: Allowed fields to sort_by
    :param offset: First element to return.
    :param limit: Maximum number of elements to return
    :param q: Query to filter by
    :param required_fields: Required fields that must appear in the response
    :return: Dictionary: {'items': Processed array, 'totalItems': Number of items, before applying offset and limit)}
    """
    if not array:
        return {'items': list(), 'totalItems': 0}

    if select:
        array = select_array(array, select=select, required_fields=required_fields)

    if search_text:
        array = search_array(array, search_text=search_text, complementary_search=complementary_search,
                             search_in_fields=search_in_fields)

    if q:
        array = filter_array_by_query(q, array)

    if sort_by == [""]:
        array = sort_array(array, sort_ascending=sort_ascending)
    elif sort_by:
        array = sort_array(array, sort_by=sort_by, sort_ascending=sort_ascending,
                           allowed_sort_fields=allowed_sort_fields)

    return {'items': cut_array(array, offset=offset, limit=limit), 'totalItems': len(array)}


def cut_array(array, offset=0, limit=common.database_limit):
    """Returns a part of the array: from offset to offset + limit.

    :param array: Array to cut.
    :param offset: First element to return.
    :param limit: Maximum number of elements to return. 0 means no cut array.
    :return: cut array.
    """

    if limit is not None:
        if limit > common.maximum_database_limit:
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


def sort_array(array, sort_by=None, sort_ascending=True, allowed_sort_fields=None):
    """Sorts an array.

    :param array: Array to sort.
    :param sort_by: Array of fields.
    :param sort_ascending: Ascending if true and descending if false
    :param allowed_sort_fields: Check sort_by with allowed_sort_fields (array).
    :return: sorted array.
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

    if allowed_sort_fields:
        check_sort_fields(set(allowed_sort_fields), set(sort_by))

    if sort_by:  # array should be a dictionary or a Class
        if type(array[0]) is dict:
            check_sort_fields(set(array[0].keys()), set(sort_by))

            return sorted(array,
                          key=lambda o: tuple(
                              o.get(a).lower() if type(o.get(a)) in (str, unicode) else o.get(a) for a in sort_by),
                          reverse=not sort_ascending)
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


def get_values(o, fields=None):
    """Converts the values of an object to an array of strings.

    :param o: Object.
    :param fields: fields to get values of (only for dictionaries)
    :return: Array of strings.
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


def search_array(array, search_text=None, complementary_search=False, search_in_fields=None):
    """Looks for the string 'text' in the elements of the array.

    :param array: Array.
    :param search_text: Text to search.
    :param complementary_search: The text must not be in the array.
    :param search_in_fields: Fields of the array to search in
    :return: Filtered array.
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


def select_array(array, select=None, required_fields=None):
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

    if required_fields is None:
        required_fields = set()
    select = set(select)

    result_list = list()
    for item in array:
        selected_fields = dict()
        missing_select = False
        # Build an entry with the filtered values
        for sel in select:
            candidate = get_nested_fields(item, sel)
            if candidate:
                selected_fields.update(candidate)
            else:
                missing_select = True
                break
        # Add required fields if the entry is not empty or missing one of the selects
        if selected_fields and not missing_select:
            selected_fields.update({req_field: item[req_field] for req_field in required_fields})
            result_list.append(selected_fields)
    if not result_list:
        raise WazuhError(1724, "{}".format(', '.join(select)))
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


def filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'.

    :param mode: Mode.
    :return: String.
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


def tail(filename, n=20):
    """Returns last 'n' lines of the file 'filename'.

    :param filename: Path to the file.
    :param n: number of lines.
    :return: Array of last lines.
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


def chmod_r(filepath, mode):
    """Recursive chmod.

    :param filepath: Path to the file.
    :param mode: file mode in octal.
    """
    chmod(filepath, mode)

    if path.isdir(filepath):
        for item in listdir(filepath):
            itempath = path.join(filepath, item)
            if path.isfile(itempath):
                chmod(itempath, mode)
            elif path.isdir(itempath):
                chmod_r(itempath, mode)


def chown_r(filepath, uid, gid):
    """Recursive chmod.

    :param filepath: Path to the file.
    :param uid: user ID.
    :param gid: group ID.
    """
    chown(filepath, uid, gid)

    if path.isdir(filepath):
        for item in listdir(filepath):
            itempath = path.join(filepath, item)
            if path.isfile(itempath):
                chown(itempath, uid, gid)
            elif path.isdir(itempath):
                chown_r(itempath, uid, gid)


def safe_move(source, target, ownership=(common.ossec_uid(), common.ossec_gid()), time=None, permissions=None):
    """Moves a file even between filesystems

    This function is useful to move files even when target directory is in a different filesystem from the source.
    Write permissions are required on target directory.

    :param source: full path to source file
    :param target: full path to target file
    :param ownership: tuple in the form (user, group) to be set up after the file is moved
    :param time: tuple in the form (addition_timestamp, modified_timestamp)
    :param permissions: string mask in octal notation. I.e.: '0o640'
    """
    # Create temp file. Move between
    tmp_path, tmp_filename = path.split(target)
    tmp_target = path.join(tmp_path, f".{tmp_filename}.tmp")
    shutil.move(source, tmp_target, copy_function=shutil.copyfile)

    try:
        # Overwrite the file atomically.
        rename(tmp_target, target)
    except OSError:
        # This is the last try when target is still in a different filesystem.
        # For example, when target is a mounted file in a Docker container
        # However, this is not an atomic operation and could lead to race conditions
        # if the file is read/written simultaneously with other processes
        shutil.move(tmp_target, target, copy_function=shutil.copyfile)

    # Set up metadata
    chown(target, *ownership)
    if permissions is not None:
        chmod(target, permissions)
    if time is not None:
        utime(target, time)


def mkdir_with_mode(name, mode=0o770):
    """Creates a directory with specified permissions.

    :param directory: directory path
    :param mode: permissions to set to the directory
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

    # append both dictonaries
    nested_dict.update(non_nested_dict)

    return nested_dict


def load_wazuh_xml(xml_path):
    with open(xml_path) as f:
        data = f.read()

    # -- characters are not allowed in XML comments
    xml_comment = re.compile(r"(<!--(.*?)-->)", flags=re.MULTILINE | re.DOTALL)
    for comment in xml_comment.finditer(data):
        good_comment = comment.group(2).replace('--', '..')
        data = data.replace(comment.group(2), good_comment)

    # < characters should be scaped as &lt; unless < is starting a <tag> or a comment

    custom_entities = {
        'backslash': '\\'
    }

    # replace every custom entity
    for character, replacement in custom_entities.items():
        data = re.sub(replacement.replace('\\', '\\\\'), f'&{character};', data)

    data = re.sub(r"<(?!/?\w+.+>|!--)", "&lt;", data)

    # replace \< by &lt;
    data = re.sub(r'\\<', '&lt;', data)

    # replace \> by &gt;
    data = re.sub(r'\\>', '&gt;', data)

    # default entities
    default_entities = ['amp', 'lt', 'gt', 'apos', 'quot']

    # & characters should be scaped if they don't represent an &entity;
    data = re.sub(f"&(?!({'|'.join(default_entities + list(custom_entities))});)", "&amp;", data)

    entities = '<!DOCTYPE xmlfile [\n' + \
               '\n'.join([f'<!ENTITY {name} "{value}">' for name, value in custom_entities.items()]) + \
               '\n]>\n'

    return fromstring(entities + '<root_tag>' + data + '</root_tag>')


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


def get_timeframe_in_seconds(timeframe):
    """Gets number of seconds from a timeframe.

    :param timeframe: Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s".
    :return: Time in seconds.
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
    """
    Filters a list of dictionaries by 'q' parameter, like as a SQL query

    :param input_array: list to be filtered
    :param q: query for filtering a list

    :return: list with processed query
    """
    def check_clause(value1: typing.Union[str, int], op: str, value2: str) -> bool:
        """
        Checks an operation between value1 and value2. 'value1' could be an
        integer, it is necessary cast value2 to integer if this happens

        :param value1: first value of the operation
        :param op: operation to be done
        :param value2: second value of the operation

        :return: True if operation is satisfied, False otherwise
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
                value2 = int(value2) if type(val) == int else value2
                if operators[op](val, value2):
                    return True
        else:
            return False

    # compile regular expression only one time when function is called
    re_get_elements = re.compile(r'([\w\-]+)(?:\.?)((?:[\w\-]*))(=|!=|<|>|~)([\w\-./:]+)') # get elements in a clause
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
                    field_name, field_subname, op, value = re_get_elements.match(and_clause).groups()
                except AttributeError:
                    raise WazuhError(1407, extra_message=f"Parameter 'q' is not valid: '{and_clause}'")

                # check if a clause is satisfied
                if field_subname:
                    if field_name in elem and field_subname in elem[field_name] and \
                            check_clause(elem[field_name][field_subname], op, value):
                        continue
                    else:
                        match = False
                        break
                else:
                    if field_name in elem and check_clause(elem[field_name], op, value):
                        continue
                    else:
                        match = False
                        break

            # if match = True, add element to output and break the loop
            if match:
                output_array.append(elem)
                break
    return output_array


class AbstractDatabaseBackend:
    """
    This class describes an abstract database backend that executes database queries
    """

    def __init__(self):
        self.conn = self.connect_to_db()

    def connect_to_db(self):
        raise NotImplementedError

    def execute(self, query, request, count=False):
        raise NotImplementedError


class SQLiteBackend(AbstractDatabaseBackend):
    """
    This class describes a sqlite database backend that executes database queries
    """

    def __init__(self, db_path):
        self.db_path = db_path
        super().__init__()

    def connect_to_db(self):
        if not glob.glob(self.db_path):
            raise WazuhInternalError(1600)
        return Connection(self.db_path)

    def _get_data(self):
        return [{k: v for k, v in db_tuple.items() if v is not None} for db_tuple in self.conn]

    def execute(self, query, request, count=False):
        self.conn.execute(query, request)
        return self._get_data() if not count else self.conn.fetch()


class WazuhDBBackend(AbstractDatabaseBackend):
    """
    This class describes a wazuh db backend that executes database queries
    """

    def __init__(self, agent_id=None, query_format='agent'):
        self.agent_id = agent_id
        self.query_format = query_format
        super().__init__()

    def connect_to_db(self):
        return WazuhDBConnection()

    def _substitute_params(self, query, request):
        """
        Substitute request parameters in query. This is only necessary when the backend is wdb. Sqlite substitutes
        parameters by itself.
        """
        for k, v in request.items():
            query = query.replace(f':{k}', f"{v}" if isinstance(v, int) else f"'{v}'")
        return query

    def _render_query(self, query):
        """Render query attending the format."""
        if self.query_format == 'mitre':
            return f'mitre sql {query}'
        else:
            return f'agent {self.agent_id} sql {query}'

    def execute(self, query, request, count=False):
        """Execute SQL query through WazuhDB socket."""
        query = self._substitute_params(query, request)
        return self.conn.execute(query=self._render_query(query), count=count)


class WazuhDBQuery(object):
    """This class describes a database query for wazuh
    """

    def __init__(self, offset, limit, table, sort, search, select, query, fields, default_sort_field, count,
                 get_data, backend, default_sort_order='ASC', filters={}, min_select_fields=set(), date_fields=set(),
                 extra_fields=set(), distinct=False):
        """
        Wazuh DB Query constructor

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: ["field1","field2"].
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        :param query: query to filter in database. Format: field operator value.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param table: table to do the query
        :param fields: all available fields
        :param default_sort_field: by default, return elements sorted by this field
        :param db_path: database path
        :param default_sort_order: by default, return elements sorted in this order
        :param min_select_fields: fields that must be always be selected because they're necessary to compute other fields
        :param count: whether to compute totalItems or not
        :param date_fields: database fields that represent a date
        :param get_data: whether to return data or not
        :param backend: Database engine to use. Possible options are 'wdb' and 'sqlite3'.
        :param distinct: Look for distinct values.
        :param agent_id: Agent to fetch information about.
        :param distinct: Look for distinct values
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
        self.min_select_fields = min_select_fields
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
            r'(\()?' +  # A ( character.
            r'([\w.]+)' +  # Field name: name of the field to look on DB
            '([' + ''.join(self.query_operators.keys()) + "]{1,2})" +  # Operator: looks for =, !=, <, > or ~.
            r"([\[\]\w _\-\.:\\/']+)" +  # Value: A string.
            r"(\))?" +  # A ) character
            "([" + ''.join(self.query_separators.keys()) + "])?"  # Separator: looks for ;, , or nothing.
        )
        self.date_regex = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        self.date_fields = date_fields
        self.extra_fields = extra_fields
        self.q = query
        self.legacy_filters = filters
        self.inverse_fields = {v: k for k, v in self.fields.items()}
        self.backend = backend

    def _clean_filter(self, query_filter):
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
            if self.limit > common.maximum_database_limit:
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
                sort_fields, allowed_sort_fields = set(self.sort['fields']), set(self.fields.keys())
                # check every element in sort['fields'] is in allowed_sort_fields
                if not sort_fields.issubset(allowed_sort_fields):
                    raise WazuhError(1403, "Allowerd sort fields: {}. Fields: {}".format(
                        sorted(allowed_sort_fields, key=str), ', '.join(sort_fields - allowed_sort_fields)
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
        """
        A query has the following pattern: field operator value separator field operator value...
        An example of query: status=never_connected;name!=pepe
            * Field must be a database field (it must be contained in self.fields variable)
            * operator must be one of = != < >
            * value can be anything
            * Separator can be either ; for 'and' or , for 'or'.

        :return: A list with processed query (self.fields)
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
                level += 1
            if close_level:
                level -= 1

            if not self._pass_filter(value):
                op_index = len(list(filter(lambda x: field in x['field'], self.query_filters)))
                self.query_filters.append({'value': None if value == "null" else value,
                                           'operator': self.query_operators[operator],
                                           'field': '{}${}'.format(field, op_index),
                                           'separator': self.query_separators[separator], 'level': level})

    def _parse_legacy_filters(self):
        """Parses legacy filters."""
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
                               for i, subvalue in enumerate(value) if not self._pass_filter(subvalue)]

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
        if field_name == "status":
            self._filter_status(q_filter)
        elif field_name in self.date_fields and not isinstance(q_filter['value'], (int, float)):
            # Filter a date, but only if it is in string (YYYY-MM-DD hh:mm:ss) format.
            # If it matches the same format as DB (timestamp integer), filter directly by value (next if cond).
            self._filter_date(q_filter, field_name)
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

            self.query += '((' if curr_level < q_filter['level'] else '('

            self._process_filter(field_name, field_filter, q_filter)

            self.query += ('))' if curr_level > q_filter['level'] else ')') + ' {} '.format(q_filter['separator'])
            curr_level = q_filter['level']
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
        # date_filter['value'] can be either a timeframe or a date in format %Y-%m-%d %H:%M:%S
        if date_filter['value'].isdigit() or re.match(r'\d+[dhms]', date_filter['value']):
            query_operator = '>' if date_filter['operator'] == '<' or date_filter['operator'] == '=' else '<'
            self.request[date_filter['field']] = get_timeframe_in_seconds(date_filter['value'])
            self.query += "({0} IS NOT NULL AND {0} {1}" \
                          " strftime('%s', 'now') - :{2}) ".format(self.fields[filter_db_name],
                                                                   query_operator,
                                                                   date_filter['field'])
        elif re.match(r'\d{4}-\d{2}-\d{2}', date_filter['value']):
            self.query += "{0} IS NOT NULL AND {0} {1} :{2}".format(self.fields[filter_db_name],
                                                                    date_filter['operator'], date_filter['field'])
            self.request[date_filter['field']] = date_filter['value']
        else:
            raise WazuhError(1412, date_filter['value'])

    def run(self):
        """Builds the query and runs it on the database"""
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

    def reset(self):
        """Resets query to its initial value. Useful when doing several requests to the same DB."""
        self.query = self._default_query()
        self.query_filters = []
        self.select -= self.extra_fields

    def _default_query(self):
        """

        :return: The default query
        """
        return "SELECT {0} FROM " + self.table if not self.distinct else "SELECT DISTINCT {0} FROM " + self.table

    def _default_count_query(self):
        return "SELECT COUNT(*) FROM ({0})"

    @staticmethod
    def _pass_filter(db_filter):
        return db_filter == "all"


class WazuhDBQueryDistinct(WazuhDBQuery):
    """Retrieves unique values for a given field."""

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
    """
    Retrieves unique values for multiple fields using group by
    """

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


@common.context_cached('system_files')
def get_files():
    folders = ['etc/rules', 'etc/decoders', 'etc/lists', 'ruleset/sca', 'ruleset/decoders', 'ruleset/rules']
    files = set()
    for folder in folders:
        for extension in '*.yml', '*.yml.disabled', '*.xml', '*.cdb':
            files.update({f.replace(common.ossec_path + '/', "") for f in glob.glob(
                path.join(common.ossec_path, folder, extension), recursive=True)})
    files.add('etc/ossec.conf')

    return files
