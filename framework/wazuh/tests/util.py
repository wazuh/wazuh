# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
from functools import wraps

from wazuh.core.config.client import Config
from wazuh.core.config.models.indexer import IndexerConfig, IndexerNode
from wazuh.core.config.models.server import NodeConfig, NodeType, ServerConfig, SSLConfig

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_default_configuration():
    """Get default configuration for the tests."""
    return Config(
        server=ServerConfig(
            nodes=['0'],
            node=NodeConfig(
                name='node_name',
                type=NodeType.MASTER,
                ssl=SSLConfig(key='example', cert='example', ca='example'),
            ),
        ),
        indexer=IndexerConfig(hosts=[IndexerNode(host='example', port=1516)], username='wazuh', password='wazuh'),
    )


class InitWDBSocketMock:
    def __init__(self, sql_schema_file):
        self.sql_schema_file = sql_schema_file
        self.__conn = self.init_db()

    def close(self):
        pass

    def init_db(self):
        sys_db = sqlite3.connect(':memory:')
        cur = sys_db.cursor()
        with open(os.path.join(test_data_path, self.sql_schema_file)) as f:
            cur.executescript(f.read())
        sys_db.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))

        return sys_db

    def execute(self, query, count=False):
        query = re.search(r'^(?:task|global|agent \d{3}) sql (.+)$', query).group(1)
        self.__conn.execute(query)
        rows = self.__conn.execute(query).fetchall()
        if len(rows) > 0 and 'COUNT(*)' in rows[0]:
            return rows[0]['COUNT(*)']
        elif len(rows) > 0 and 'COUNT(DISTINCT id)' in rows[0]:
            return rows[0]['COUNT(DISTINCT id)']
        elif count:
            return next(iter(rows[0].values()))
        return rows


def get_fake_database_data(sql_file):
    """Create a fake database."""
    memory_db = sqlite3.connect(':memory:')
    cur = memory_db.cursor()
    with open(os.path.join(test_data_path, sql_file)) as f:
        cur.executescript(f.read())

    return memory_db


def RBAC_bypasser(**kwargs_decorator):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return decorator
