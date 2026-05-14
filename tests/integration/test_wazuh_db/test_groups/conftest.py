"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import time

from wazuh_testing.utils.agent_groups import create_group, delete_group
from wazuh_testing.utils.db_queries.global_db import create_or_update_agent, set_agent_group, delete_agent


@pytest.fixture()
def create_groups(test_metadata):
    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)


@pytest.fixture()
def pre_insert_agents_into_group():
    for i in range(2):
        id = i + 1
        name = 'Agent-test' + str(id)
        date = time.time()
        create_or_update_agent(agent_id=id, name=name, date_add=date)
        set_agent_group(sync_status="syncreq", id=id, group=f"Test_group{id}")

    yield

    delete_agent()
