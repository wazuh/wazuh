# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import json
import re
import socket
import struct
from typing import List

from wazuh.core import common
from wazuh.core.common import MAX_SOCKET_BUFFER_SIZE
from wazuh.core.exception import WazuhInternalError, WazuhError

DATE_FORMAT = re.compile(r'\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}')


class WazuhDBConnection:
    """
    Represents a connection to the wdb socket
    """

    def __init__(self, request_slice=500, max_size=6144):
        """
        Constructor
        """
        self.socket_path = common.wdb_socket_path
        self.request_slice = request_slice
        self.max_size = max_size
        self.__conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.__conn.connect(self.socket_path)
        except OSError as e:
            raise WazuhInternalError(2005, e)

    def __query_input_validation(self, query):
        """
        Checks input queries have the correct format

        Accepted query formats:
        - agent 000 sql sql_sentence
        - global sql sql_sentence
        """
        query_elements = query.split(" ")
        sql_first_index = 2 if query_elements[0] == 'agent' else 1

        if query_elements[0] == 'mitre':
            input_val_errors = [
                (query_elements[sql_first_index] == 'sql',
                 'Incorrect WDB request type'),
                (query_elements[2] == 'select',
                 'Wrong SQL query for Mitre database')
            ]
        elif query_elements[sql_first_index] == 'rootcheck':
            input_val_errors = [
                (query_elements[sql_first_index+1] == 'delete' or query_elements[sql_first_index+1] == 'save',
                 'Only "save" or "delete" requests can be sent to WDB')
            ]
        else:
            input_val_errors = [
                (query_elements[sql_first_index] == 'sql', "Incorrect WDB request type."),
                (query_elements[0] == 'agent' or query_elements[0] == 'global',
                 "The {} database is not valid".format(query_elements[0])),
                (query_elements[1].isdigit() if query_elements[0] == 'agent' else True,
                 "Incorrect agent ID {}".format(query_elements[1])),
                (query_elements[sql_first_index + 1] == 'select' or query_elements[sql_first_index + 1] == 'delete' or
                 query_elements[sql_first_index + 1] == 'update', 'Only "select", "delete" or "update" requests can be '
                                                                'sent to WDB'),
                (not ';' in query, "Found a not valid symbol in database query: ;")
            ]

        for check, error_text in input_val_errors:
            if not check:
                raise WazuhError(2004, error_text)

    def _send(self, msg, raw=False):
        """
        Send a message to the wdb socket
        """
        msg = struct.pack('<I', len(msg)) + msg.encode()
        self.__conn.send(msg)

        # Get the data size (4 bytes)
        data = self.__conn.recv(4)
        data_size = struct.unpack('<I', data[0:4])[0]

        data = self._recvall(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)

        # Max size socket buffer is 64KB
        if data_size >= MAX_SOCKET_BUFFER_SIZE:
            raise ValueError

        if data[0] == "err":
            raise WazuhError(2003, data[1])
        elif raw:
            return data
        else:
            return json.loads(data[1], object_hook=WazuhDBConnection.json_decoder)

    def _recvall(self, data_size, buffer_size=4096):
        data = bytearray()
        while len(data) < data_size:
            packet = self.__conn.recv(buffer_size)
            if not packet:
                return data
            data.extend(packet)
        return data

    @staticmethod
    def json_decoder(dct):
        result = {}
        for k, v in dct.items():
            if v == "(null)":
                continue
            if isinstance(v, str) and DATE_FORMAT.match(v):
                result[k] = datetime.datetime.strptime(v, '%Y/%m/%d %H:%M:%S')
            else:
                result[k] = v

        return result

    def __query_lower(self, query):
        """
        Convert a query to lower except the words between ""
        """

        to_lower = True
        new_query = ""

        for i in query:
            if to_lower and i != "'":
                new_query += i.lower()
            elif to_lower and i == "'":
                new_query += i
                to_lower = False
            elif not to_lower and i != "'":
                new_query += i
            elif not to_lower and i == "'":
                new_query += i
                to_lower = True

        return new_query

    def delete_agents_db(self, agents_id: List[str]):
        """
        Delete agents db through wazuh-db service

        :param agents_id: strings of agents
        :return: dict received from wazuh db in the form: {"agents": {"ID": "MESSAGE"}}, where MESSAGE may be one
        of the following:
        - Ok
        - Invalid agent ID
        - DB waiting for deletion
        - DB not found
        """
        return self._send(f"wazuhdb remove {' '.join(agents_id)}")

    def run_wdb_command(self, command):
        """Run command in wdb and return list of retrieved information.

        The response of wdb socket contains 2 elements, a STATUS and a PAYLOAD.
        State value can be:
            ok {payload}    -> Successful query with no pending data
            due {payload}   -> Successful query with pending data
            err {message}   -> Unsuccessful query

        Parameters
        ----------
        command : str
            Command to be executed inside wazuh-db

        Returns
        -------
        response : list
            List with JSON results
        """
        response = []

        while True:
            status, payload = self._send(command, raw=True)
            if status == 'err':
                raise WazuhInternalError(2007, extra_message=payload)
            if payload != '[]':
                response.append(payload)
            # Exit if there are no items left to return
            if status == 'ok':
                break

        return response

    def execute(self, query, count=False, delete=False, update=False):
        """
        Sends a sql query to wdb socket
        """
        def send_request_to_wdb(query_lower, step, off, response):
            try:
                request = query_lower.replace(':limit', 'limit {}'.format(step)).replace(':offset', 'offset {}'.format(off))
                response.extend(self._send(request))
            except ValueError:
                # if the step is already 1, it can't be divided
                if step == 1:
                    raise WazuhInternalError(2007)
                send_request_to_wdb(query_lower, step // 2, off, response)
                # Add step // 2 remaining when the step is odd to avoid losing information
                send_request_to_wdb(query_lower, step // 2 + step % 2, step // 2 + off, response)

        query_lower = self.__query_lower(query)

        self.__query_input_validation(query_lower)

        # only for delete queries
        if delete:
            regex = re.compile(r"\w+ \d+? (sql delete from ([a-z0-9,_ ]+)|\w+ delete$)")
            if regex.match(query_lower) is None:
                raise WazuhError(2004, "Delete query is wrong")
            return self._send(query_lower)

        # only for update queries
        if update:
            # regex = re.compile(r"\w+ \d+? sql update ([a-z0-9,*_ ]+) set value = '([a-z0-9,*_ ]+)' where key (=|like)?"
            regex = re.compile(r"\w+ \d+? sql update ([\w\d,*_ ]+) set value = '([\w\d,*_ ]+)' where key (=|like)?"
                               r" '([a-z0-9,*_%\- ]+)'")
            if regex.match(query_lower) is None:
                raise WazuhError(2004, "Update query is wrong")
            return self._send(query_lower)

        # Remove text inside 'where' clause to prevent finding reserved words (offset/count)
        query_without_where = re.sub(r'where \([^()]*\)', 'where ()', query_lower)

        # if the query has already a parameter limit / offset, divide using it
        offset = 0
        if re.search(r'offset \d+', query_without_where):
            offset = int(re.compile(r".* offset (\d+)").match(query_lower).group(1))
            # Replace offset with a wildcard
            query_lower = ' :offset'.join(query_lower.rsplit((' offset {}'.format(offset)), 1))

        if not re.search(r'.?select count\([\w \*]+\)( as [^,]+)? from', query_without_where):
            lim = 0
            if re.search(r'limit \d+', query_without_where):
                lim = int(re.compile(r".* limit (\d+)").match(query_lower).group(1))
                # Replace limit with a wildcard
                query_lower = ' :limit'.join(query_lower.rsplit((' limit {}'.format(lim)), 1))

            regex = re.compile(r"\w+(?: \d*|)? sql select ([A-Z a-z0-9,*_` \.\-%\(\):\']+?) from")
            select = regex.match(query_lower).group(1)
            gb_regex = re.compile(r"(group by [^\s]+)")
            countq = query_lower.replace(select, "count(*)", 1).replace(":limit", "").replace(":offset", "")
            try:
                group_by = gb_regex.search(query_lower)
                if group_by:
                    countq = countq.replace(group_by.group(1), '')
            except IndexError:
                pass

            try:
                total = list(self._send(countq)[0].values())[0]
            except IndexError:
                total = 0

            limit = lim if lim != 0 else total

            response = []
            step = limit if limit < self.request_slice and limit > 0 else self.request_slice
            if ':limit' not in query_lower:
                query_lower += ' :limit'
            if ':offset' not in query_lower:
                query_lower += ' :offset'

            try:
                for off in range(offset, limit + offset, step):
                    send_request_to_wdb(query_lower, step, off, response)
            except ValueError as e:
                raise WazuhError(2006, str(e))
            except WazuhError as e:
                raise e
            except Exception as e:
                raise WazuhInternalError(2007, str(e))

            if count:
                return response, total
            else:
                return response
        else:
            return list(self._send(query_lower)[0].values())[0]
