"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import time

from wazuh_testing.utils import database
from wazuh_testing.utils.db_queries.global_db import delete_agent


@pytest.fixture(scope='module')
def clean_databases():
    yield
    database.delete_dbs()


@pytest.fixture(scope='module')
def clean_registered_agents():
    delete_agent()
    time.sleep(5)
