# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from unittest.mock import patch, PropertyMock, MagicMock

from wazuh.core.exception import WazuhException
from importlib import reload
from os.path import join, dirname, realpath

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.database import *

test_data_path = join(dirname(realpath(__file__)), 'data', 'test_database')
db_name = 'schema_global_test.sql'


def test_sql_compatibility():
    """Check if an exception is raised if an incompatible version of Sqlite is being used."""
    with patch('sqlite3.sqlite_version', '2.0.0.0'):
        with patch('wazuh.core.common.wazuh_uid'):
            with patch('wazuh.core.common.wazuh_gid'):
                with pytest.raises(WazuhException, match=".* 2001 .*"):
                    # Since the module has been imported before calling this function
                    # it's necessary to reload it with the patched sqlite_version
                    reload(sys.modules['wazuh.core.database'])


@pytest.mark.parametrize('max_attempts', [50, 100, 200])
@patch('sqlite3.connect', return_value=sqlite3.connect(":memory:"))
@patch.object(Connection, 'max_attempts', create=True, new_callable=PropertyMock)
@patch.object(Connection, 'db_path', create=True, new_callable=PropertyMock)
def test_connection__init__(mock_db_path, mock_max_attempts, mock_connect, max_attempts):
    """Check if the Connection class is initialized properly.

    Parameters
    ----------
    mock_db_path: PropertyMock
        Mock Connection's db_path attribute.
    mock_max_attempts: PropertyMock
        Mock Connection's max_attempts attribute.
    mock_connect: MagicMock
        Mock sqlite3 connect method.
    max_attempts: int
        Connection's max number of retries when trying to execute a query.
    """

    with patch('wazuh.core.database.isfile', return_value=True):
        Connection(max_attempts=max_attempts)
    mock_max_attempts.assert_called_with(max_attempts)

    for x in [mock_connect, mock_db_path, mock_connect]:
        x.assert_called()


@patch('sqlite3.connect')
def test_connection__init__ko(mock_connect):
    """Check that an exception is raised if Connection's constructor is called with invalid parameters.

    Parameters
    ----------
    mock_connect: MagicMock
        Mock sqlite3 connect method.
    """
    with pytest.raises(WazuhException, match=".* 2000 .*"):
        Connection(db_path='not_a_file')


@pytest.fixture
def create_test_connection():
    with patch('sqlite3.connect', return_value=sqlite3.connect(':memory:')), patch('wazuh.core.database.isfile',
                                                                                   return_value=True):
        con = Connection()
        with open(join(test_data_path, db_name)) as f:
            con._Connection__cur.executescript(f.read())

    return con


def test_connection__iter__(create_test_connection):
    """Check if Connection's __iter__ method is using calling cursor's __iter__ method.

    Parameters
    ----------
        create_test_connection: Fixture
            Fixture used to prepare a connection with a sqlite DB on memory.
    """
    con = create_test_connection
    assert con.__iter__() == con._Connection__cur.__iter__()


@pytest.mark.parametrize('query, value, expected_result, multiple', [
    ('SELECT id FROM agent WHERE name = ?', 'agent-7', 7, False),
    ('SELECT id, name, os_name FROM agent WHERE name = "pending-agent"', None, 4, False),
    ('SELECT name FROM agent WHERE id >= ?', 7, [{'name': 'agent-7'}, {'name': 'agent-8'}], True),
    ('SELECT name FROM agent WHERE id < 2', None, [{'name': 'master'}, {'name': 'agent-1'}], True)
])
def test_connection_execute(create_test_connection, query, value, expected_result, multiple):
    """Check if Connection's execute method is working properly when requesting one row.

    Parameters
    ----------
        create_test_connection: Fixture
            Fixture used to prepare a connection with a sqlite DB on memory.
        query: str
            Query to be executed by the dbms.
        value: str or None or int
            Value to add to the prepared statement.
        expected_result: int or list of dict
            Expected return result of the execution of the specified query.
        multiple: bool
            If the result will consist on multiple values.
    """
    con = create_test_connection

    if value:
        con.execute(query, (value,))
    else:
        con.execute(query)

    if not multiple:
        assert expected_result == con.fetch()
    else:
        assert expected_result == con.fetch_all()


def test_connection_execute_ko_attempts():
    """Check if Connection's execute method raises an exception when the number of retries is greater than the one
    specified in the max_retries parameter.
    """
    with patch('sqlite3.connect'), patch('wazuh.core.database.isfile', return_value=True):
        con = Connection(max_attempts=0)

    with pytest.raises(WazuhInternalError):
        con._Connection__cur.execute.side_effect = sqlite3.OperationalError('database is locked')
        con.execute('test str')


@pytest.mark.parametrize('query, value', [
    ('SELECT * FROM agent WHERE unexistent_column > ?', 100),
    ('not a sqlite query', None)
])
def test_connection_execute_ko_sqlite_request(create_test_connection, query, value):
    """Check if the execution of a wrong query raises an sqlite exception.

    Parameters
    ----------
        create_test_connection: Fixture
            Fixture used to prepare a connection with a sqlite DB on memory.
        query: str
            Wrong query that's going to be sent to the DBMS.
        value: int
            Value to add to the prepared statement.
    """
    con = create_test_connection
    with pytest.raises(WazuhError, match=".* 2003 .*"):
        if not value:
            con.execute(query)
        else:
            con.execute(query, value)
