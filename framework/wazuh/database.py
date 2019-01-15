#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from os.path import isfile
from distutils.version import LooseVersion
import sqlite3

# Check SQL compatibility: >= 3.7.0.0
if LooseVersion(sqlite3.sqlite_version) < LooseVersion('3.7.0.0'):
    msg = str(sqlite3.sqlite_version)
    msg += "\nTry to export the internal SQLite library:"
    msg += "\nexport LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{0}/framework/lib".format(common.ossec_path)
    raise WazuhException(2001, msg)


class Connection:
    """
    Represents a connection against a database
    """

    def __init__(self, db_path=common.database_path_global, busy_sleep=0.001, max_attempts=1000):
        """
        Constructor
        """
        self.db_path = db_path

        if not isfile(db_path):
            raise WazuhException(2000)

        self.max_attempts = max_attempts

        self.__conn = sqlite3.connect(database = db_path, timeout = busy_sleep)
        self.__cur = self.__conn.cursor()

    def __iter__(self):
        """
        Iterating support
        """
        return self.__cur.__iter__()

    def begin(self):
        """
        Begin transaction
        """
        self.__cur.execute('BEGIN')

    def commit(self):
        """
        Commit changes
        """
        self.__conn.commit()

    def execute(self, query, *args):
        """
        Execute query

        :param query: Query string.
        :param args: Query values.
        """
        n_attempts = 0
        while n_attempts <= self.max_attempts:
            try:
                if args:
                    self.__cur.execute(query, *args)
                else:
                    self.__cur.execute(query)

                break

            except sqlite3.OperationalError as e:
                error_text = str(e)
                if error_text == 'database is locked':
                    n_attempts += 1
                else:
                    raise WazuhException(2003, error_text)

            except Exception as e:
                raise WazuhException (2003, str(e))

            if n_attempts > self.max_attempts:
                raise WazuhException(2002, error_text)

    def fetch(self):
        """
        Return next tuple
        """
        return self.__cur.fetchone()

    def vacuum(self):
        """
        Rebuild the entire database: reduce size and defragment
        """
        self.__cur.execute('VACUUM')
