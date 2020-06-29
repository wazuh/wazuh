

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhInternalError
from os.path import isfile
from distutils.version import LooseVersion
import sqlite3
import sys
import time
# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str

# Check SQL compatibility: >= 3.7.0.0
if LooseVersion(sqlite3.sqlite_version) < LooseVersion('3.7.0.0'):
    msg = str(sqlite3.sqlite_version)
    msg += "\nTry to export the internal SQLite library:"
    msg += "\nexport LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{0}/framework/lib".format(common.ossec_path)
    raise WazuhInternalError(2001, extra_message=msg)


class Connection:
    """
    Represents a connection against a database
    """

    def __init__(self, db_path=common.database_path_global, busy_sleep=0.001, max_attempts=50):
        """
        Constructor
        """
        self.db_path = db_path

        if not isfile(db_path):
            raise WazuhInternalError(2000)

        self.max_attempts = max_attempts

        self.__conn = sqlite3.connect(database = db_path, timeout = busy_sleep)
        self.__conn.text_factory = lambda x: unicode(x, "utf-8", "ignore")
        self.__conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
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
                    time.sleep(0.1)
                else:
                    raise WazuhError(2003, extra_message=error_text)

            except Exception as e:
                raise WazuhError(2003, extra_message=str(e))

            if n_attempts > self.max_attempts:
                raise WazuhInternalError(2002, extra_message=error_text)

    def fetch(self):
        """
        Return next tuple value
        """
        next_val = self.__cur.fetchone()
        return next(iter(next_val.values())) if isinstance(next_val, dict) else next_val

    def fetch_all(self):
        """
        Return all tuples
        """
        return self.__cur.fetchall()

    def vacuum(self):
        """
        Rebuild the entire database: reduce size and defragment
        """
        self.__cur.execute('VACUUM')
