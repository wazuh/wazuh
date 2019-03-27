#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import sqlite3
import os
import pytest
from wazuh.exception import WazuhException

from wazuh.agent import Agent

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


class InitAgent:

    def __init__(self):
        """
        Sets up necessary test environment for agents:
            * One active agent.
            * One pending agent.
            * One never connected agent.
            * One disconnected agent.

        :return: None
        """
        self.global_db = sqlite3.connect(':memory:')
        self.cur = self.global_db.cursor()
        with open(os.path.join(test_data_path, 'schema_global_test.sql')) as f:
            self.cur.executescript(f.read())

        self.never_connected_fields = {'status', 'name', 'ip', 'registerIP', 'node_name', 'dateAdd', 'id'}
        self.pending_fields = self.never_connected_fields | {'manager', 'lastKeepAlive'}
        self.manager_fields = self.pending_fields | {'version', 'os'}
        self.active_fields = self.manager_fields | {'group', 'mergedSum', 'configSum'}
        self.manager_fields -= {'registerIP'}


@pytest.fixture(scope='module')
def test_data():
    return InitAgent()


def check_agent(test_data, agent):
    """
    Checks a single agent is correct
    """
    assert all(map(lambda x: x is not None, agent.values()))
    assert 'status' in agent
    assert 'id' in agent
    if agent['id'] == '000':
        assert agent.keys() == test_data.manager_fields
    elif agent['status'] == 'Active' or agent['status'] == 'Disconnected':
        assert agent.keys() == test_data.active_fields
    elif agent['status'] == 'Pending':
        assert agent.keys() == test_data.pending_fields
    elif agent['status'] == 'Never connected':
        assert agent.keys() == test_data.never_connected_fields
    else:
        raise Exception("Agent status not known: {}".format(agent['status']))


def test_get_agents_overview_default(test_data):
    """
    Test to get all agents using default parameters
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview()

        # check number of agents
        assert agents['totalItems'] == 6
        # check the return dictionary has all necessary fields

        for agent in agents['items']:
            # check no values are returned as None
            check_agent(test_data, agent)


@pytest.mark.parametrize("select, status, older_than, offset", [
    ({'id', 'dateAdd'}, 'all', None, 0),
    ({'id', 'ip', 'registerIP'}, 'all', None, 1),
    ({'id', 'registerIP'}, 'all', None, 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'Active,Pending', None, 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'Disconnected', None, 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'Disconnected', '1s', 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'Disconnected', '2h', 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'all', '15m', 2),
    ({'id', 'ip', 'lastKeepAlive'}, 'Active', '15m', 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'Active,Pending', '15m', 1),
    ({'id', 'ip', 'lastKeepAlive'}, ['Active', 'Pending'], '15m', 1)
])
def test_get_agents_overview_select(test_data, select, status, older_than, offset):
    """
    Test get_agents_overview function with multiple select parameters
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview(select={'fields': select}, filters={'status': status, 'older_than': older_than}, offset=offset)
        assert all(map(lambda x: x.keys() == select, agents['items']))


@pytest.mark.parametrize("query", [
    "ip=172.17.0.201",
    "ip=172.17.0.202",
    "ip=172.17.0.202;registerIP=any",
    "status=Disconnected;lastKeepAlive>34m",
    "(status=Active,status=Pending);lastKeepAlive>5m",
])
def test_get_agents_overview_query(test_data, query):
    """
    Test filtering by query
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview(q=query)
        assert len(agents['items']) == 1


@pytest.mark.parametrize("search, totalItems", [
    ({'value': 'any', 'negation': 0}, 3),
    ({'value': 'any', 'negation': 1}, 3),
    ({'value': '202', 'negation': 0}, 1),
    ({'value': '202', 'negation': 1}, 5),
    ({'value': 'master', 'negation': 1}, 2)
])
def test_get_agents_overview_search(test_data, search, totalItems):
    """
    Test searching by IP and Register IP
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview(search=search)
        assert len(agents['items']) == totalItems


@pytest.mark.parametrize("status, older_than, totalItems, exception", [
    ('active', '9m', 1, None),
    ('all', '1s', 5, None),
    ('pending,neverconnected', '30m', 1, None),
    (55, '30m', 0, 1729)
])
def test_get_agents_overview_status_olderthan(test_data, status, older_than, totalItems, exception):
    """
    Test filtering by status
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db
        kwargs = {'filters': {'status': status, 'older_than': older_than},
                  'select': {'fields': ['name', 'id', 'status', 'lastKeepAlive', 'dateAdd']}}

        if exception is None:
            agents = Agent.get_agents_overview(**kwargs)
            assert agents['totalItems'] == totalItems
        else:
            with pytest.raises(WazuhException, match=f'.* {exception} .*'):
                Agent.get_agents_overview(**kwargs)
