# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sqlite3
import os
import re

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


class InitWDBSocketMock:
    def __init__(self, sql_schema_file):
        self.sql_schema_file = sql_schema_file
        self.__conn = self.init_db()

    def init_db(self):
        sys_db = sqlite3.connect(':memory:')
        cur = sys_db.cursor()
        with open(os.path.join(test_data_path, self.sql_schema_file)) as f:
            cur.executescript(f.read())
        sys_db.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))

        return sys_db

    def execute(self, query, count=False):
        query = re.search(r'^agent \d{3} sql (.+)$', query).group(1)
        self.__conn.execute(query)
        rows = self.__conn.execute(query).fetchall()
        if len(rows) > 0 and 'COUNT(*)' in rows[0]:
            return rows[0]['COUNT(*)']
        elif count:
            return next(iter(rows[0].values()))
        return rows
