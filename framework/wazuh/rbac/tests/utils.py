# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from importlib import reload
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy import orm as sqlalchemy_orm
from sqlalchemy.sql import text


def create_memory_db(sql_file, session, test_data_path):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(text(line))
                session.commit()


def init_db(schema, test_data_path):
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.orm as orm

                    # Clear mappers
                    sqlalchemy_orm.clear_mappers()
                    # Invalidate in-memory database
                    orm.db_manager.close_sessions()
                    orm.db_manager.connect(orm.DB_FILE)
                    orm.db_manager.sessions[orm.DB_FILE].close()
                    orm.db_manager.engines[orm.DB_FILE].dispose()

                    reload(orm)
                    orm.db_manager.connect(orm.DB_FILE)
                    orm.db_manager.create_database(orm.DB_FILE)
                    orm.db_manager.insert_default_resources(orm.DB_FILE)
                    import wazuh.rbac.decorators as decorators
                    from wazuh.tests.util import RBAC_bypasser

                    decorators.expose_resources = RBAC_bypasser
    try:
        create_memory_db(schema, orm.db_manager.sessions[orm.DB_FILE], test_data_path)
    except OperationalError:
        pass
