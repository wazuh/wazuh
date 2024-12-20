# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import contextlib
import datetime
import json
import re
import socket
import struct
from typing import List, Union

from wazuh.core import common
from wazuh.core.common import MAX_SOCKET_BUFFER_SIZE
from wazuh.core.exception import WazuhError, WazuhInternalError

DATE_FORMAT = re.compile(r'\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}')


class AsyncWazuhDBConnection:
    """Represent an async connection to the wdb socket."""

    def __init__(self, loop: asyncio.AbstractEventLoopPolicy = None):
        """Class constructor.

        Parameters
        ----------
        loop : asyncio.AbstractEventLoopPolicy
            Event loop. It's optional and can always be determined automatically when self.open_connection() is
            awaited from a coroutine.
        """
        self.socket_path = common.WDB_SOCKET
        self.loop = loop
        self._reader = None
        self._writer = None

    async def open_connection(self):
        """Establish a Unix socket connection."""
        self._reader, self._writer = await asyncio.open_unix_connection(path=self.socket_path)

    def close(self):
        """Close writer socket."""
        if self._writer is not None:
            self._writer.close()

    def __del__(self):
        self.close()

    async def _send(self, msg, raw=False):
        """Format and send message to wazuh-db socket without blocking event loop.

        Parameters
        ----------
        msg : str
            Message to be sent to wazuh-db.
        raw : bool
            If `True`, the status message from wazuh-db is included in the response.

        Returns
        -------
        str, list
            Result for the request sent to wazuh-db.
        """
        try:
            if None in [self._writer, self._reader]:
                await self.open_connection()

            # Send message.
            encoded_msg = msg.encode(encoding='utf-8')
            packed_msg = struct.pack('<I', len(encoded_msg)) + encoded_msg
            self._writer.write(packed_msg)
            await self._writer.drain()

            # Read the response when it's ready.
            try:
                data = await self._reader.readexactly(4)
                data_size = struct.unpack('<I', data[0:4])[0]
                data = await self._reader.readexactly(data_size)
                data = data.decode(encoding='utf-8', errors='ignore').split(' ', 1)
            except asyncio.IncompleteReadError as e:
                raise WazuhInternalError(2010, extra_message=e)

            if raw:
                return data
            elif data[0] == 'err':
                raise WazuhError(2003, data[1])
            else:
                return json.loads(data[1], object_hook=WazuhDBConnection.json_decoder)
        except (FileNotFoundError, ConnectionError) as e:
            with contextlib.suppress(Exception):
                await self.open_connection()
            raise WazuhInternalError(2005, extra_message=e)

    async def run_wdb_command(self, command):
        """Run command in wdb and return list of retrieved information.

        The response of wdb socket can contain 2 elements, a STATUS and a PAYLOAD.
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
        result = await self._send(command, raw=True)

        # result[0] -> status
        # result[1] -> payload
        if len(result) > 1:
            if result[0] == 'err':
                raise WazuhInternalError(2007, extra_message=result[1])

        else:
            if result[0] != 'ok':
                raise WazuhInternalError(2007)

        return result


class WazuhDBConnection:
    """Represent a connection to the wdb socket."""

    def __init__(self, request_slice=500):
        """Class constructor.

        Parameters
        ----------
        request_slice : int
            Maximum number of items to request from wazuh-db on the first call.
        """
        self.socket_path = common.WDB_SOCKET
        self.request_slice = request_slice
        try:
            self.__conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__conn.connect(self.socket_path)
        except OSError as e:
            raise WazuhInternalError(2005, e)

    def close(self):
        self.__conn.close()

    def __del__(self):
        self.close()

    def __query_input_validation(self, query: str):
        """Check input queries have the correct format

        Accepted query formats:
        - agent 001 sql sql_sentence
        - global sql sql_sentence

        Parameters
        ----------
        query : str
            Query to check.

        Raises
        ------
        WazuhError(2004)
            Database query not valid.
        """
        query_elements = query.split(' ')
        sql_first_index = 2 if query_elements[0] == 'agent' else 1

        if query_elements[0] == 'mitre':
            input_val_errors = [
                (query_elements[sql_first_index] == 'sql', 'Incorrect WDB request type'),
                (query_elements[2] == 'select', 'Wrong SQL query for Mitre database'),
            ]
        elif query_elements[sql_first_index] == 'rootcheck':
            input_val_errors = [
                (
                    query_elements[sql_first_index + 1] == 'delete' or query_elements[sql_first_index + 1] == 'save',
                    'Only "save" or "delete" requests can be sent to WDB',
                )
            ]
        else:
            input_val_errors = [
                (query_elements[sql_first_index] == 'sql', 'Incorrect WDB request type.'),
                (
                    query_elements[0] == 'agent' or query_elements[0] == 'global' or query_elements[0] == 'task',
                    'The {} database is not valid'.format(query_elements[0]),
                ),
                (
                    query_elements[1].isdigit() if query_elements[0] == 'agent' else True,
                    'Incorrect agent ID {}'.format(query_elements[1]),
                ),
                (
                    query_elements[sql_first_index + 1] == 'select'
                    or query_elements[sql_first_index + 1] == 'delete'
                    or query_elements[sql_first_index + 1] == 'update',
                    'Only "select", "delete" or "update" requests can be ' 'sent to WDB',
                ),
                (';' not in query, 'Found a not valid symbol in database query: ;'),
            ]

        for check, error_text in input_val_errors:
            if not check:
                raise WazuhError(2004, error_text)

    def _send(self, msg: str, raw: bool = False) -> dict:
        """Send a message to the wdb socket.

        Parameters
        ----------
        msg : str
            Message to send.
        raw : bool
            Respond in raw format.

        Raises
        ------
        WazuhInternalError(2009)
            Pagination error. Response from wazuh-db was over the maximum socket buffer size.
        WazuhError(2003)
            Error in wdb request.

        Returns
        -------
        dict
            Data received.
        """
        encoded_msg = msg.encode(encoding='utf-8')
        packed_msg = struct.pack('<I', len(encoded_msg)) + encoded_msg
        # Send msg
        self.__conn.send(packed_msg)

        # Get the data size (4 bytes)
        data = self.__conn.recv(4)
        data_size = struct.unpack('<I', data[0:4])[0]

        data = self._recvall(data_size).decode(encoding='utf-8', errors='ignore').split(' ', 1)

        # Max size socket buffer is 64KB
        if data_size >= MAX_SOCKET_BUFFER_SIZE:
            raise WazuhInternalError(2009)

        if data[0] == 'err':
            raise WazuhError(2003, data[1])
        elif raw:
            return data
        else:
            return WazuhDBConnection.loads(data[1])

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
            if v == '(null)':
                continue
            if isinstance(v, str) and DATE_FORMAT.match(v):
                result[k] = datetime.datetime.strptime(v, '%Y/%m/%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
            else:
                result[k] = v

        return result

    @staticmethod
    def loads(string: str) -> dict:
        """Custom implementation for the JSON loads method with the class decoder.
        This method takes care of the possible emtpy objects that may be load.

        Parameters
        ----------
        string : str
            String response from `wazuh-db`. It must be a dumped JSON.

        Returns
        -------
        dict
            JSON object.
        """
        data = json.loads(string, object_hook=WazuhDBConnection.json_decoder)
        if '"(null)"' in string:
            # To prevent empty dictionaries, clean data if there was any `"(null)"` within the string
            data = [item for item in data if item]

        return data

    def __query_lower(self, query: str) -> str:
        """Convert a query to lower except the words between "".

        Parameters
        ----------
        query : str
            Query to be converted.

        Returns
        -------
        str
            New query.
        """
        to_lower = True
        new_query = ''

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

    def delete_agents_db(self, agents_id: List[str]) -> dict:
        """Delete agents db through wazuh-db service.

        Parameters
        ----------
        agents_id : List[str]
            List of agents.

        Returns
        -------
        dict
            Dict received from wazuh db in the form: {"agents": {"ID": "MESSAGE"}}, where MESSAGE may be one of the
            following:
                - Ok
                - Invalid agent ID
                - DB waiting for deletion
                - DB not found
        """
        return self._send(f"wazuhdb remove {' '.join(agents_id)}")

    def send(self, query: str, raw: bool = True) -> Union[str, dict]:
        """Send a message to the wdb socket.

        Parameters
        ----------
        query : str
            Query to be executed in wazuh-db.
        raw : bool
            Whether to process the response.

        Returns
        -------
        str or dict
            Result of the query.
        """
        return self._send(query, raw)

    def execute(self, query, count=False, delete=False, update=False):
        """Send a SQL query to wdb socket."""

        def send_request_to_wdb(query_lower, step, off, response):
            try:
                request = query_lower.replace(':limit', 'limit {}'.format(step)).replace(
                    ':offset', 'offset {}'.format(off)
                )
                request_response = self._send(request, raw=True)[1]
                response.extend(WazuhDBConnection.loads(request_response))
                if len(request_response) * 2 < MAX_SOCKET_BUFFER_SIZE:
                    return step * 2
                else:
                    return step
            except WazuhInternalError:
                # if the step is already 1, it can't be divided
                if step == 1:
                    raise WazuhInternalError(2009)

                send_request_to_wdb(query_lower, step // 2, off, response)
                # Add step // 2 remaining when the step is odd to avoid losing information
                return send_request_to_wdb(query_lower, step // 2 + step % 2, step // 2 + off, response)

        query_lower = self.__query_lower(query)

        self.__query_input_validation(query_lower)

        # only for delete queries
        if delete:
            regex = re.compile(r'\w+ \d+? (sql delete from ([a-z0-9,_ ]+)|\w+ delete$)')
            if regex.match(query_lower) is None:
                raise WazuhError(2004, 'Delete query is wrong')
            return self._send(query_lower)

        # only for update queries
        if update:
            regex = re.compile(
                r"\w+ \d+? sql update ([\w\d,*_ ]+) set value = '([\w\d,*_ ]+)' where key (=|like)?"
                r" '([a-z0-9,*_%\- ]+)'"
            )
            if regex.match(query_lower) is None:
                raise WazuhError(2004, 'Update query is wrong')
            return self._send(query_lower)

        # Remove text inside 'where' clause to prevent finding reserved words (offset/count)
        query_without_where = re.sub(r'where \([^()]*\)', 'where ()', query_lower)

        # if the query has already a parameter limit / offset, divide using it
        offset = 0
        if re.search(r'offset \d+', query_without_where):
            offset = int(re.compile(r'.* offset (\d+)').match(query_lower).group(1))
            # Replace offset with a wildcard
            query_lower = ' :offset'.join(query_lower.rsplit((' offset {}'.format(offset)), 1))

        if not re.search(r'.?select count\([\w \*]+\)( as [^,]+)? from', query_without_where):
            lim = 0
            if re.search(r'limit \d+', query_without_where):
                lim = int(re.compile(r'.* limit (\d+)').match(query_lower).group(1))
                # Replace limit with a wildcard
                query_lower = ' :limit'.join(query_lower.rsplit((' limit {}'.format(lim)), 1))

            regex = re.compile(r'\w+(?: \d*|)? sql select ([A-Z a-z0-9,*_` \.\-%\(\):\']+?) from')
            select = regex.match(query_lower).group(1)
            gb_regex = re.compile(r'(group by [^\s]+)')
            countq = query_lower.replace(select, 'count(*)', 1).replace(':limit', '').replace(':offset', '')
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

            limit = lim if lim != 0 and lim < total else total

            response = []
            if ':limit' not in query_lower:
                query_lower += ' :limit'
            if ':offset' not in query_lower:
                query_lower += ' :offset'

            try:
                off = offset
                while off < limit + offset:
                    step = limit if self.request_slice > limit > 0 else self.request_slice
                    # Min() used to avoid fetching more items than the maximum specified in `limit`.
                    self.request_slice = send_request_to_wdb(
                        query_lower, min(limit + offset - off, step), off, response
                    )
                    off += step
            except ValueError as e:
                raise WazuhError(2006, str(e))
            except (WazuhError, WazuhInternalError) as e:
                raise e
            except Exception as e:
                raise WazuhInternalError(2007, str(e))

            if count:
                return response, total
            else:
                return response
        else:
            return list(self._send(query_lower)[0].values())[0]
