#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import hashlib
import json
import sys
from os.path import abspath, dirname, join, realpath
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

import db.orm as orm

# Overwrite ORM's engine to avoid creating the local database file during the tests
orm.engine = create_engine('sqlite:///', echo=False)
orm.session = orm.sessionmaker(bind=orm.engine)()

test_data_path = join(dirname(dirname(realpath(__file__))), 'data')
test_last_dates_path = join(test_data_path, 'last_date_files')


@pytest.fixture(scope='function')
def create_and_teardown_db():
    """Create the database and purge it after the test execution."""
    orm.create_db()
    yield
    orm.Base.metadata.drop_all(orm.engine)


@pytest.fixture(scope='function')
def teardown_db():
    """Do not create a database before the test but purge it after the execution."""
    yield
    orm.Base.metadata.drop_all(orm.engine)


@pytest.mark.parametrize(
    'expected_table_names, expected_columns',
    [
        (
            ['graph', 'log_analytics', 'storage'],
            ['md5', 'query', 'min_processed_date', 'max_processed_date'],
        )
    ],
)
def test_create_db(expected_table_names, expected_columns, teardown_db):
    """Check if the create_db function works as expected."""
    # Check there is no tables available
    inspector = inspect(orm.engine)
    assert inspector.get_table_names() == []

    # Create the tables
    orm.create_db()

    # Validate the tables and their structure
    inspector = inspect(orm.engine)
    table_names = inspector.get_table_names()
    assert table_names == expected_table_names
    for table in table_names:
        assert [x['name'] for x in inspector.get_columns(table)] == expected_columns


def test_add_get_row(create_and_teardown_db):
    """Test the ORM is able to insert row into the different tables and retrieve them as a whole and individually as
    expected."""
    # Add several entries and validate them
    for table in [orm.Graph, orm.LogAnalytics, orm.Storage]:
        for id_ in range(3):
            md5 = hashlib.md5(f'{table.__tablename__}{id_}'.encode()).hexdigest()
            original_datetime = '2022-01-01T23:59:59.1234567Z'
            row = table(
                md5=md5,
                query='',
                min_processed_date=original_datetime,
                max_processed_date=original_datetime,
            )
            orm.add_row(row=row)
            row = orm.get_row(table=table, md5=md5)
            assert row
            assert row.md5 == md5
            assert row.min_processed_date == original_datetime
            assert row.max_processed_date == original_datetime

            # Update the row
            new_datetime = '1999-01-01T23:59:59.1234567Z'
            orm.update_row(
                table=table,
                md5=md5,
                min_date=new_datetime,
                max_date=new_datetime,
                query='query',
            )
            row = orm.get_row(table=table, md5=md5)
            assert row.min_processed_date == new_datetime
            assert row.max_processed_date == new_datetime

        assert len(orm.get_all_rows(table=table)) == 3

    # Try to obtain a non-existing item
    assert orm.get_row(table=orm.Graph, md5='non-existing') is None


def test_add_ko(create_and_teardown_db):
    """Test the add_row function by attempting to insert a row with None values. The commit operation should raise an
    IntegrityError that must be caught."""
    row = orm.Graph(md5='test', query='', min_processed_date=None, max_processed_date=None)
    with pytest.raises(orm.AzureORMError):
        orm.add_row(row=row)
    assert len(orm.get_all_rows(orm.Graph)) == 0


def test_get_rows_ko(create_and_teardown_db):
    """Ensure the get_rows function fails when using an invalid database."""
    orm.Base.metadata.drop_all(orm.engine)
    with pytest.raises(orm.AzureORMError):
        assert orm.get_row(table=orm.Graph, md5='')
    with pytest.raises(orm.AzureORMError):
        orm.get_all_rows(table=orm.Graph)


@patch('db.orm.session.commit', side_effect=IntegrityError)
def test_update_row_ko(create_and_teardown_db):
    """Ensure the update_row function catch exceptions when trying to commit the changes."""
    with pytest.raises(orm.AzureORMError):
        orm.update_row(orm.Graph, md5='test', min_date='', max_date='')


@pytest.mark.parametrize(
    'last_dates_file_path',
    [
        (join(test_last_dates_path, 'last_dates.json')),
        (join(test_last_dates_path, 'last_dates_graph.json')),
        (join(test_last_dates_path, 'last_dates_log_analytics.json')),
        (join(test_last_dates_path, 'last_dates_storage.json')),
        (join(test_last_dates_path, 'last_dates_old.json')),
        (join(test_last_dates_path, 'last_dates_clean.json')),
        (join(test_last_dates_path, 'last_dates_with_invalid_min_max.json')),
        (join(test_last_dates_path, 'last_dates_old_invalid_value.json')),
    ],
)
def test_load_dates_json(last_dates_file_path):
    """Check the load_dates_json function properly loads the contents of the files, regardless of their structure as
    long as it is a valid one."""
    with patch('db.orm.last_dates_path', new=last_dates_file_path):
        last_dates_dict = orm.load_dates_json()
        for key in last_dates_dict.keys():
            assert isinstance(last_dates_dict[key], dict)
            for md5 in last_dates_dict[key].keys():
                assert isinstance(last_dates_dict[key][md5], dict)
                assert set(last_dates_dict[key][md5].keys()) == {'min', 'max'}


@patch('db.orm.exists', return_value=False)
@patch('builtins.open')
def test_load_dates_json_no_file(mock_open, mock_exists):
    """Check the load_dates_json handles exception as expected when no file is provided."""
    assert orm.load_dates_json() == orm.last_dates_default_contents
    mock_exists.assert_called_once()


@pytest.mark.parametrize(
    'last_dates_file_path',
    [(join(test_last_dates_path, 'last_dates_invalid.json'))],
)
def test_load_dates_json_ko(last_dates_file_path):
    """Check the load_dates_json handles exception as expected when an invalid file is provided."""
    with patch('db.orm.last_dates_path', new=last_dates_file_path):
        with pytest.raises(json.JSONDecodeError):
            orm.load_dates_json()


@pytest.mark.parametrize(
    'file_exists, file_size',
    [
        (True, 0),
        (True, 100),
        (False, 100),
    ],
)
@patch('db.orm.create_db')
@patch('db.orm.migrate_from_last_dates_file')
def test_check_integrity(mock_migrate, mock_create_db, create_and_teardown_db, file_exists, file_size):
    """Ensure that the check_integrity functions is able to create a new database file."""
    with patch('db.orm.exists', return_value=file_exists):
        with patch('db.orm.getsize', return_value=file_size):
            orm.check_database_integrity()
            mock_create_db.assert_called()
            if file_exists and file_size > 0:
                mock_migrate.assert_called()
            else:
                mock_migrate.assert_not_called()


def test_check_integrity_ko(teardown_db):
    """Ensure the check_integrity function returns a False value when the migration process fails."""
    with patch('db.orm.exists'):
        with patch('db.orm.getsize', return_value=100):
            with patch(
                'db.orm.migrate_from_last_dates_file',
                side_effect=Exception,
            ):
                assert orm.check_database_integrity() is False


@pytest.mark.parametrize(
    'last_dates_file_path',
    [
        (join(test_last_dates_path, 'last_dates.json')),
        (join(test_last_dates_path, 'last_dates_graph.json')),
        (join(test_last_dates_path, 'last_dates_log_analytics.json')),
        (join(test_last_dates_path, 'last_dates_storage.json')),
        (join(test_last_dates_path, 'last_dates_old.json')),
        (join(test_last_dates_path, 'last_dates_clean.json')),
    ],
)
def test_migrate_from_last_dates_file(last_dates_file_path, create_and_teardown_db):
    """Test the last_dates file migration functionality."""
    items = orm.get_all_rows(table=orm.Graph)
    assert len(items) == 0

    with open(last_dates_file_path, 'r') as file:
        test_file_contents = json.load(file)

    with patch('db.orm.last_dates_path', new=last_dates_file_path):
        orm.migrate_from_last_dates_file()

    # Validate the contents of each table
    for table in [orm.Graph, orm.LogAnalytics, orm.Storage]:
        items = orm.get_all_rows(table=table)
        if table.__tablename__ in test_file_contents:
            assert len(items) == len(test_file_contents[table.__tablename__].keys())
            for item in items:
                try:
                    assert test_file_contents[table.__tablename__][item.md5]['min'] == item.min_processed_date
                    assert test_file_contents[table.__tablename__][item.md5]['max'] == item.max_processed_date
                except (KeyError, TypeError):
                    # Old last_dates.json structure
                    assert test_file_contents[table.__tablename__][item.md5] == item.max_processed_date


def test_min_max_valid():
    json_content = {'min': '2022-03-07T15:12:56.98Z', 'max': '2022-03-17T15:12:56.98Z'}

    result = orm.get_min_max_values(json_content)
    assert result == json_content


def test_min_max_invalid_min():
    json_content = {'min': '0', 'max': '2022-03-17T15:12:56.98Z'}

    result = orm.get_min_max_values(json_content)
    assert result == {'min': json_content['max'], 'max': json_content['max']}


def test_min_max_invalid_max():
    json_content = {'min': '2022-03-17T15:12:56.98Z', 'max': '0'}

    result = orm.get_min_max_values(json_content)
    assert result == {'min': json_content['min'], 'max': json_content['min']}


def test_min_max_invalid_max_and_min(monkeypatch):
    json_content = {'min': '0', 'max': '0'}
    expected_value = orm.get_default_min_max_values()
    monkeypatch.setattr(orm, 'get_default_min_max_values', lambda: expected_value)

    result = orm.get_min_max_values(json_content)
    assert result == {'min': expected_value, 'max': expected_value}


def test_min_max_valid_old_format():
    json_content = '2022-03-04T15:12:56.98Z'

    result = orm.get_min_max_values(json_content)
    assert result == {'min': json_content, 'max': json_content}


def test_min_max_invalid_old_format(monkeypatch):
    json_content = '0'
    expected_value = orm.get_default_min_max_values()
    monkeypatch.setattr(orm, 'get_default_min_max_values', lambda: expected_value)

    result = orm.get_min_max_values(json_content)
    assert result == {'min': expected_value, 'max': expected_value}
