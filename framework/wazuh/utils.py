#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.database import Connection
from wazuh import common
from tempfile import mkstemp
from subprocess import call, CalledProcessError
from os import remove, chmod, chown, path, listdir, close, mkdir, curdir
from datetime import datetime, timedelta
import hashlib
import json
import stat
import re
import errno
from itertools import groupby, chain
from xml.etree.ElementTree import fromstring
from operator import itemgetter
import glob
import sys
# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str

try:
    from subprocess import check_output
except ImportError:
    def check_output(arguments, stdin=None, stderr=None, shell=False):
        temp_f = mkstemp()
        returncode = call(arguments, stdin=stdin, stdout=temp_f[0], stderr=stderr, shell=shell)
        close(temp_f[0])
        file_o = open(temp_f[1], 'r')
        cmd_output = file_o.read()
        file_o.close()
        remove(temp_f[1])

        if returncode != 0:
            error_cmd = CalledProcessError(returncode, arguments[0])
            error_cmd.output = cmd_output
            raise error_cmd
        else:
            return cmd_output


def previous_month(n=1):
    """
    Returns the first date of the previous n month.

    :param n: Number of months.
    :return: First date of the previous n month.
    """

    date = datetime.today().replace(day=1)  # First day of current month

    for i in range(0, int(n)):
        date = (date - timedelta(days=1)).replace(day=1)  # (first_day - 1) = previous month

    return date.replace(hour=00, minute=00, second=00, microsecond=00)


def execute(command):
    """
    Executes a command. It is used to execute ossec commands.

    :param command: Command as list.
    :return: If output.error !=0 returns output.data, otherwise launches a WazuhException with output.error as error code and output.message as description.
    """

    try:
        output = check_output(command)
    except CalledProcessError as error:
        output = error.output
    except Exception as e:
        raise WazuhException(1002, "{0}: {1}".format(command, e))  # Error executing command

    try:
        output_json = json.loads(output)
    except Exception as e:
        raise WazuhException(1003, command)  # Command output not in json

    keys = output_json.keys()  # error and (data or message)
    if 'error' not in keys or ('data' not in keys and 'message' not in keys):
        raise WazuhException(1004, command)  # Malformed command output

    if output_json['error'] != 0:
        raise WazuhException(output_json['error'], output_json['message'], True)
    else:
        return output_json['data']


def cut_array(array, offset, limit):
    """
    Returns a part of the array: from offset to offset + limit.
    :param array: Array to cut.
    :param offset: First element to return.
    :param limit: Maximum number of elements to return. 0 means no cut array.
    :return: cut array.
    """

    if limit is not None:
        if limit > common.maximum_database_limit:
            raise WazuhException(1405, str(limit))
        elif limit == 0:
            raise WazuhException(1406)

    elif not array or limit is None:
        return array

    offset = int(offset)
    limit = int(limit)

    if offset < 0:
        raise WazuhException(1400)
    elif limit < 1:
        raise WazuhException(1401)
    else:
        return array[offset:offset + limit]


def sort_array(array, sort_by=None, order='asc', allowed_sort_fields=None):
    """
    Sorts an array.

    :param array: Array to sort.
    :param sort_by: Array of fields.
    :param order: asc or desc.
    :param allowed_sort_fields: Check sort_by with allowed_sort_fields (array).
    :return: sorted array.
    """
    def check_sort_fields(allowed_sort_fields, sort_by):
        # Check if every element in sort['fields'] is in allowed_sort_fields
        if not sort_by.issubset(allowed_sort_fields):
            incorrect_fields = ', '.join(sort_by - allowed_sort_fields)
            raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(', '.join(allowed_sort_fields), incorrect_fields))

    if not array:
        return array

    if order.lower() == 'desc':
        order_desc = True
    elif order.lower() == 'asc':
        order_desc = False
    else:
        raise WazuhException(1402)

    if allowed_sort_fields:
        check_sort_fields(set(allowed_sort_fields), set(sort_by))

    if sort_by:  # array should be a dictionary or a Class
        if type(array[0]) is dict:
            check_sort_fields(set(array[0].keys()), set(sort_by))

            return sorted(array,
                          key=lambda o: tuple(o.get(a).lower() if type(o.get(a)) in (str,unicode) else o.get(a) for a in sort_by),
                          reverse=order_desc)
        else:
            return sorted(array,
                          key=lambda o: tuple(getattr(o, a).lower() if type(getattr(o, a)) in (str,unicode) else getattr(o, a) for a in sort_by),
                          reverse=order_desc)
    else:
        if type(array) is set or (type(array[0]) is not dict and 'class \'wazuh' not in str(type(array[0]))):
            return sorted(array, reverse=order_desc)
        else:
            raise WazuhException(1404)


def get_values(o, fields=None):
    """
    Converts the values of an object to an array of strings.
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


def search_array(array, text, negation=False, fields=None):
    """
    Looks for the string 'text' in the elements of the array.

    :param array: Array.
    :param text: Text to search.
    :param negation: the text must not be in the array.
    :param fields: fields of the array to search in
    :return: True or False.
    """

    found = []

    for item in array:

        values = get_values(o=item, fields=fields)

        if not negation:
            for v in values:
                if text.lower() in v:
                    found.append(item)
                    break
        else:
            not_in_values = True
            for v in values:
                if text.lower() in v:
                    not_in_values = False
                    break
            if not_in_values:
                found.append(item)

    return found


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
    """
    Convert a file's mode to a string of the form '-rwxrwxrwx'.
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
    """
    Returns last 'n' lines of the file 'filename'.
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
    """
    Recursive chmod.
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
    """
    Recursive chmod.
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


def mkdir_with_mode(name, mode=0o770):
    """
    Creates a directory with specified permissions.

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
        if tail == curdir:           # xxx/newdir/. exists if xxx/newdir exists
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


def get_hash(filename, hash_algorithm='md5'):
    # check hash algorithm
    try:
        algorithm_list = hashlib.algorithms_available
    except Exception as e:
        algorithm_list = hashlib.algorithms

    if not hash_algorithm in algorithm_list:
        raise WazuhException(1723, "Available algorithms are {0}.".format(', '.join(algorithm_list)))

    hashing = hashlib.new(hash_algorithm)

    try:
        with open(filename, 'rb') as f:
            hashing.update(f.read())
    except IOError:
        return None

    return hashing.hexdigest()


def get_fields_to_nest(fields, force_fields=[], split_character="_"):
    nest = {k:set(filter(lambda x: x != k, chain.from_iterable(g)))
             for k,g in groupby(map(lambda x: x.split(split_character), sorted(fields)),
             key=lambda x:x[0])}
    nested = filter(lambda x: len(x[1]) > 1 or x[0] in force_fields, nest.items())
    nested = [(field,{(subfield, split_character.join([field,subfield])) for subfield in subfields}) for field, subfields in nested]
    non_nested = set(filter(lambda x: x.split(split_character)[0] not in map(itemgetter(0), nested), fields))
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
    nested = {k:list(filter(lambda x: x != k, chain.from_iterable(g)))
             for k,g in groupby(map(lambda x: x.split(split_character), sorted(data.keys())),
             key=lambda x:x[0])}

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
    nested_dict = {f:{sf:data['{0}{2}{1}'.format(f,sf,split_character)] for sf in sfl} for f,sfl
                  in nested.items() if len(sfl) > 1 or f in force_fields}

    # create a dictionary with the non nested fields
    # non_nested_dict = {'board_serial': 'BSS-0123456789'}
    non_nested_dict = {f:data[f] for f in data.keys() if f.split(split_character)[0]
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
        good_comment = comment.group(2).replace('--','..')
        data = data.replace(comment.group(2), good_comment)

    # < characters should be scaped as &lt; unless < is starting a <tag> or a comment
    data = re.sub(r"<(?!/?\w+.+>|!--)", "&lt;", data)

    # & characters should be scaped if they don't represent an &entity;
    data = re.sub(r"&(?!\w+;)", "&amp;", data)

    return fromstring('<root_tag>' + data + '</root_tag>')


class WazuhVersion:

    def __init__(self, version):

        pattern = "v?(\d)\.(\d)\.(\d)\-?(alpha|beta|rc)?(\d*)"
        m = re.match(pattern, version)

        if m:
            self.__mayor = m.group(1)
            self.__minor = m.group(2)
            self.__patch = m.group(3)
            self.__dev = m.group(4)
            self.__dev_ver = m.group(5)
        else:
            raise ValueError("Invalid version format.")

    def to_array(self):
        array = [self.__mayor]
        array.extend(self.__minor)
        array.extend(self.__patch)
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
    """
    Gets number of seconds from a timeframe.
    :param timeframe: Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s".

    :return: Time in seconds.
    """
    if not timeframe.isdigit():
        if 'h' not in timeframe and 'd' not in timeframe and 'm' not in timeframe and 's' not in timeframe:
            raise WazuhException(1411, timeframe)

        regex, seconds = re.compile(r'(\d+)(\w)'), 0
        time_equivalence_seconds = {'d': 86400, 'h': 3600, 'm': 60, 's':1}
        for time, unit in regex.findall(timeframe):
            # it's not necessarry to check whether the unit is in the dictionary, because it's been validated before.
            seconds += int(time) * time_equivalence_seconds[unit]
    else:
        seconds = int(timeframe)

    return seconds


class WazuhDBQuery(object):
    """
    This class describes a database query for wazuh
    """
    def __init__(self, offset, limit, table, sort, search, select, query, fields, default_sort_field, db_path, count,
                 get_data, default_sort_order='ASC', filters={}, min_select_fields=set(), date_fields=set(), extra_fields=set()):
        """
        Wazuh DB Query constructor

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
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
        """
        self.offset = offset
        self.limit = limit
        self.table = table
        self.sort = sort
        self.search = search
        self.select = None if not select else select.copy()
        self.fields = fields.copy()
        self.query = self._default_query()
        self.request = {}
        self.default_sort_field = default_sort_field
        self.default_sort_order = default_sort_order
        self.query_filters = []
        self.count = count
        self.data = get_data
        self.total_items = 0
        self.min_select_fields = min_select_fields
        self.query_operators = {"=":"=", "!=":"!=", "<":"<", ">":">", "~":'LIKE'}
        self.query_separators = {',':'OR',';':'AND','':''}
        # To correctly turn a query into SQL, a regex is used. This regex will extract all necessary information:
        # For example, the following regex -> (name!=wazuh;id>5),group=webserver <- would return 3 different matches:
        #   (name != wazuh ;
        #    id   > 5      ),
        #    group=webserver
        self.query_regex = re.compile(
            r'(\()?' +                                                     # A ( character.
            '([\w.]+)' +                                                   # Field name: name of the field to look on DB
            '([' + ''.join(self.query_operators.keys()) + "]{1,2})" +      # Operator: looks for =, !=, <, > or ~.
            "([\w _\-.:/]+)" +                                             # Value: A string.
            "(\))?" +                                                      # A ) character
            "([" + ''.join(self.query_separators.keys())+"])?"             # Separator: looks for ;, , or nothing.
        )
        self.date_regex = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        self.date_fields = date_fields
        self.extra_fields = extra_fields
        self.q = query
        self.legacy_filters = filters
        self.inverse_fields = {v: k for k, v in self.fields.items()}
        if not glob.glob(db_path):
            raise WazuhException(1600)
        self.conn = Connection(db_path)


    def _add_limit_to_query(self):
        if self.limit:
            if self.limit > common.maximum_database_limit:
                raise WazuhException(1405, str(self.limit))
            self.query += ' LIMIT :offset,:limit'
            self.request['offset'] = self.offset
            self.request['limit'] = self.limit
        elif self.limit == 0: # 0 is not a valid limit
            raise WazuhException(1406)


    def _sort_query(self, field):
        return '{} {}'.format(self.fields[field], self.sort['order'])


    def _add_sort_to_query(self):
        if self.sort:
            if self.sort['fields']:
                sort_fields, allowed_sort_fields = set(self.sort['fields']), set(self.fields.keys())
                # check every element in sort['fields'] is in allowed_sort_fields
                if not sort_fields.issubset(allowed_sort_fields):
                    raise WazuhException(1403, "Allowerd sort fields: {}. Fields: {}".format(
                        allowed_sort_fields, ', '.join(sort_fields - allowed_sort_fields)
                    ))
                self.query += ' ORDER BY ' + ','.join([self._sort_query(i) for i in sort_fields])
            else:
                self.query += ' ORDER BY {0} {1}'.format(self.default_sort_field, self.sort['order'])
        else:
            self.query += ' ORDER BY {0} {1}'.format(self.default_sort_field, self.default_sort_order)


    def _add_search_to_query(self):
        if self.search:
            self.query += " AND NOT" if bool(self.search['negation']) else ' AND'
            self.query += " (" + " OR ".join(x + ' LIKE :search' for x in self.fields.values()) + ')'
            self.query = self.query.replace('WHERE  AND', 'WHERE')
            self.request['search'] = '%{0}%'.format(self.search['value'])


    def _parse_select_filter(self, select_fields):
        if select_fields:
            set_select_fields = set(select_fields['fields'])
            set_fields_keys = set(self.fields.keys()) - self.extra_fields
            if not set_select_fields.issubset(set_fields_keys):
                raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}". \
                                     format(', '.join(self.fields.keys()), ', '.join(set_select_fields - set_fields_keys)))

            select_fields['fields'] = set_select_fields
        else:
            select_fields = {'fields': set(self.fields.keys())}

        return select_fields


    def _add_select_to_query(self):
        self.select = self._parse_select_filter(self.select)


    def _parse_query(self):
        """
        A query has the following pattern: field operator value separator field operator value...
        An example of query: status=never connected;name!=pepe
            * Field must be a database field (it must be contained in self.fields variable)
            * operator must be one of = != < >
            * value can be anything
            * Separator can be either ; for 'and' or , for 'or'.

        :return: A list with processed query (self.fields)
        """
        if not self.query_regex.match(self.q):
            raise WazuhException(1407, self.q)

        level = 0
        for open_level, field, operator, value, close_level, separator in self.query_regex.findall(self.q):
            if field not in self.fields.keys():
                raise WazuhException(1408, "Available fields: {}. Field: {}".format(', '.join(self.fields), field))
            if operator not in self.query_operators:
                raise WazuhException(1409, "Valid operators: {}. Used operator: {}".format(', '.join(self.query_operators), operator))

            if open_level:
                level += 1
            if close_level:
                level -= 1

            if not self._pass_filter(value):
                self.query_filters.append({'value': None if value == "null" else value, 'operator': self.query_operators[operator],
                                 'field': '{}${}'.format(field, len(list(filter(lambda x: field in x['field'], self.query_filters)))),
                                 'separator': self.query_separators[separator], 'level': level})


    def _parse_legacy_filters(self):
        """
        Parses legacy filters.
        """
        legacy_filters_as_list = {name: value.split(',') if isinstance(value, unicode) or isinstance(value,str) else value for name, value in self.legacy_filters.items()}
        self.query_filters += [{'value': None if subvalue == "null" else subvalue, 'field': '{}${}'.format(name,i), 'operator': '=', 'separator': 'OR' if len(value) > 1 else 'AND', 'level': 0}
                               for name, value in legacy_filters_as_list.items() for subvalue,i in zip(value, range(len(value))) if not self._pass_filter(subvalue)]
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
        elif field_name in self.date_fields and not self.date_regex.match(q_filter['value']):
            # filter a date, but only if it is in timeframe format.
            # If it matches the same format as DB (YYYY-MM-DD hh:mm:ss), filter directly by value (next if cond).
            self._filter_date(q_filter, field_name)
        else:
            if q_filter['value'] is not None:
                self.request[field_filter] = q_filter['value'] if field_name != "version" else re.sub(
                    r'([a-zA-Z])([v])', r'\1 \2', q_filter['value'])
                if q_filter['operator'] == 'LIKE':
                    self.request[field_filter] = '%{}%'.format(self.request[field_filter])
                self.query += '{} {} :{}'.format(self.fields[field_name], q_filter['operator'], field_filter)
                if not field_filter.isdigit():
                    # filtering without being uppercase/lowercase sensitive
                    self.query += ' COLLATE NOCASE'
            else:
                self.query += '{} IS null'.format(self.fields[field_name])


    def _add_filters_to_query(self):
        self._parse_filters()
        curr_level = 0
        for q_filter in self.query_filters:
            field_name = q_filter['field'].split('$',1)[0]
            field_filter = q_filter['field'].replace('.','_')

            self.query += '((' if curr_level < q_filter['level'] else '('

            self._process_filter(field_name, field_filter, q_filter)

            self.query += ('))' if curr_level > q_filter['level'] else ')') + ' {} '.format(q_filter['separator'])
            curr_level = q_filter['level']


    def _get_total_items(self):
        self.conn.execute(self.query.format(self._default_count_query()), self.request)
        self.total_items = self.conn.fetch()[0]


    def _get_data(self):
        self.conn.execute(self.query.format(','.join(map(lambda x: self.fields[x], self.select['fields'] | self.min_select_fields))), self.request)


    def _format_data_into_dictionary(self):
        return {'items': [{key:value for key,value in zip(self.select['fields'] | self.min_select_fields, db_tuple)
                           if value is not None} for db_tuple in self.conn], 'totalItems': self.total_items}


    def _filter_status(self, status_filter):
        raise NotImplementedError


    def _filter_date(self, date_filter, filter_db_name):
        # date_filter['value'] can be either a timeframe or a date in format %Y-%m-%d %H:%M:%S
        if date_filter['value'].isdigit() or re.match(r'\d+[dhms]', date_filter['value']):
            query_operator = '>' if date_filter['operator'] == '<' or date_filter['operator'] == '=' else '<'
            self.request[date_filter['field']] = get_timeframe_in_seconds(date_filter['value'])
            self.query += "({0} IS NOT NULL AND CAST(strftime('%s', {0}) AS INTEGER) {1}" \
                          " CAST(strftime('%s', 'now', 'localtime') AS INTEGER) - :{2}) ".format(self.fields[filter_db_name],
                                                                                                 query_operator,
                                                                                                 date_filter['field'])
        elif re.match(r'\d{4}-\d{2}-\d{2}', date_filter['value']):
            self.query += "{0} IS NOT NULL AND {0} {1} :{2}".format(self.fields[filter_db_name], date_filter['operator'], date_filter['field'])
            self.request[date_filter['field']] = date_filter['value']
        else:
            raise WazuhException(1412, date_filter['value'])


    def run(self):
        """
        Builds the query and runs it on the database
        """

        self._add_select_to_query()
        self._add_filters_to_query()
        self._add_search_to_query()
        if self.count:
            self._get_total_items()
        self._add_sort_to_query()
        self._add_limit_to_query()
        if self.data:
            self._get_data()
            return self._format_data_into_dictionary()


    def reset(self):
        """
        Resets query to its initial value. Useful when doing several requests to the same DB.
        """
        self.query = self._default_query()
        self.query_filters = []
        self.select['fields'] -= self.extra_fields


    def _default_query(self):
        """
        :return: The default query
        """
        return "SELECT {0} FROM " + self.table


    def _default_count_query(self):
        return "COUNT(*)"


    @staticmethod
    def _pass_filter(db_filter):
        return db_filter == "all"


class WazuhDBQueryDistinct(WazuhDBQuery):
    """
    Retrieves unique values for a given field.
    """

    def _default_query(self):
        return "SELECT DISTINCT {0} FROM " + self.table


    def _default_count_query(self):
        return "COUNT (DISTINCT {0})".format(','.join(map(lambda x: self.fields[x], self.select['fields'])))


    def _add_filters_to_query(self):
        WazuhDBQuery._add_filters_to_query(self)
        self.query += ' WHERE ' if not self.q and 'WHERE' not in self.query else ' AND '
        self.query += ' AND '.join(["{0} IS NOT null AND {0} != ''".format(self.fields[field]) for field in self.select['fields']])


    def _add_select_to_query(self):
        if len(self.select['fields']) > 1:
            raise WazuhException(1410)

        WazuhDBQuery._add_select_to_query(self)


    def _format_data_into_dictionary(self):
        return {'totalItems': self.total_items, 'items': [db_tuple[0] for db_tuple in self.conn]}


class WazuhDBQueryGroupBy(WazuhDBQuery):
    """
    Retrieves unique values for multiple fields using group by
    """

    def __init__(self, filter_fields, offset, limit, table, sort, search, select, query, fields, default_sort_field, db_path, count,
                 get_data, default_sort_order='ASC', filters={}, min_select_fields=set(), date_fields=set(), extra_fields=set()):
        WazuhDBQuery.__init__(self, offset, limit, table, sort, search, select, query, fields, default_sort_field,
                              db_path, count, get_data, default_sort_order, filters, min_select_fields, date_fields, extra_fields)
        self.filter_fields = filter_fields


    def _get_total_items(self):
        # take total items without grouping, and add the group by clause just after getting total items
        WazuhDBQuery._get_total_items(self)
        self.select['fields'].add('count')
        self.inverse_fields['COUNT(*)'] = 'count'
        self.fields['count'] = 'COUNT(*)'
        self.query += ' GROUP BY ' + ','.join(map(lambda x: self.fields[x], self.filter_fields['fields']))


    def _add_select_to_query(self):
        WazuhDBQuery._add_select_to_query(self)
        self.filter_fields = self._parse_select_filter(self.filter_fields)
        self.select['fields'] = self.select['fields'] & self.filter_fields['fields']
