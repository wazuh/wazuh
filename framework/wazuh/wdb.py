#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from os import strerror
import socket
import re
import json
import struct

class WazuhDBConnection:
    """
    Represents a connection to the wdb socket
    """

    def __init__(self, request_slice=20, max_size=6144):
        """
        Constructor
        """
        self.socket_path = common.wdb_socket_path
        self.request_slice = request_slice
        self.max_size = max_size
        self.__conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.__conn.connect(self.socket_path)
        except socket.error as e:
            raise WazuhException(2005, strerror(e[0]))


    def __query_input_validation(self, query):
        """
        Checks input queries have the correct format
        """
        query_elements = query.split(" ")
        sql_first_index = 2 if query_elements[0] == 'agent' else 1

        input_val_errors = [
            (query_elements[sql_first_index] == 'sql', "Incorrect WDB request type."),
            (query_elements[0] == 'agent' or query_elements[0] == 'global', "The {} database is not valid".format(query_elements[0])),
            (query_elements[1].isdigit() if query_elements[0] == 'agent' else True, "Incorrect agent ID {}".format(query_elements[1])),
            (query_elements[sql_first_index+1] == 'select' or query_elements[sql_first_index+1] == 'delete' or
             query_elements[sql_first_index+1] == 'update', "The API can only send select requests to WDB"),
            (not ';' in query, "Found a not valid symbol in database query: ;")
        ]

        for check, error_text in input_val_errors:
            if not check:
                raise WazuhException(2004, error_text)


    def __send(self, msg):
        """
        Sends a message to the wdb socket
        """
        msg = struct.pack('<I', len(msg)) + msg.encode()
        self.__conn.send(msg)

        # Get the data size (4 bytes)
        data = self.__conn.recv(4)
        data_size = struct.unpack('<I',data[0:4])[0]

        data = self.__conn.recv(data_size).decode('utf-8').split(" ", 1)

        if data[0] == "err":
            raise WazuhException(2003, data[1])
        else:
            return json.loads(data[1])


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



    def execute(self, query, count=False, delete=False, update=False):
        """
        Sends a sql query to wdb socket
        """
        def send_request_to_wdb(query_lower, step, off, response):
            try:
                request = "{} limit {} offset {}".format(query_lower, step, off)
                response.extend(self.__send(request))
            except ValueError:
                # if the step is already 1, it can't be divided
                if step == 1:
                    raise WazuhException(2007)
                send_request_to_wdb(query_lower, step // 2, off, response)
                send_request_to_wdb(query_lower, step // 2, step // 2 + off, response)

        query_lower = self.__query_lower(query)

        self.__query_input_validation(query_lower)

        # only for delete queries
        if delete:
            regex = re.compile(r"\w+ \d+? sql delete from ([a-z0-9,_ ]+)")
            if regex.match(query_lower) is None:
                raise WazuhException(2004, "Delete query is wrong")
            return self.__send(query_lower)

        # only for update queries
        if update:
            # regex = re.compile(r"\w+ \d+? sql update ([a-z0-9,*_ ]+) set value = '([a-z0-9,*_ ]+)' where key (=|like)?"
            regex = re.compile(r"\w+ \d+? sql update ([\w\d,*_ ]+) set value = '([\w\d,*_ ]+)' where key (=|like)?"
                               r" '([a-z0-9,*_%\- ]+)'")
            if regex.match(query_lower) is None:
                raise WazuhException(2004, "Update query is wrong")
            return self.__send(query_lower)

        # if the query has already a parameter limit / offset, divide using it
        offset = 0
        if 'offset' in query_lower:
            offset = int(re.compile(r".* offset (\d+)").match(query_lower).group(1))
            query_lower = query_lower.replace(" offset {}".format(offset), "")

        if 'count' not in query_lower:
            lim = 0
            if 'limit' in query_lower:
                lim  = int(re.compile(r".* limit (\d+)").match(query_lower).group(1))
                query_lower = query_lower.replace(" limit {}".format(lim), "")

            regex = re.compile(r"\w+ \d+? sql select ([a-z0-9,*_ ]+) from")
            select = regex.match(query_lower).group(1)
            countq = query_lower.replace(select, "count(*)", 1)
            total = list(self.__send(countq)[0].values())[0]

            limit = lim if lim != 0 else total

            response = []
            step = limit if limit < self.request_slice and limit > 0  else self.request_slice
            try:
                for off in range(offset, limit+offset, step):
                    send_request_to_wdb(query_lower, step, off, response)
            except ValueError as e:
                raise WazuhException(2006, str(e))
            except Exception as e:
                raise WazuhException(2007, str(e))

            if count:
                return response, total
            else:
                return response
        else:
            return self.__send(query_lower)[0].values()[0]
