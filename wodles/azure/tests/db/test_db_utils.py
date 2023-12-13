#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import sys
from datetime import datetime
from os.path import abspath, dirname
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

from azure_utils import DATETIME_MASK
from db import orm
from db.utils import create_new_row, update_row_object

PAST_DATE = '2022-01-01T12:00:00.000000Z'
PRESENT_DATE = '2022-06-15T12:00:00.000000Z'
FUTURE_DATE = '2022-12-31T12:00:00.000000Z'


@pytest.mark.parametrize(
    'min_date, max_date',
    [
        (PAST_DATE, PRESENT_DATE),
        (PAST_DATE, FUTURE_DATE),
        (PRESENT_DATE, PRESENT_DATE),
        (PRESENT_DATE, FUTURE_DATE),
        (FUTURE_DATE, FUTURE_DATE),
    ],
)
@patch('db.orm.update_row')
@patch('db.orm.get_row')
def test_update_row_object(mock_get, mock_update, min_date, max_date):
    """Test update_row_object alter the database values when corresponds."""
    mock_table = MagicMock(__tablename__='')
    mock_get.return_value = MagicMock(min_processed_date=PRESENT_DATE, max_processed_date=PRESENT_DATE)
    update_row_object(table=mock_table, md5_hash='', new_min=min_date, new_max=max_date, query='')
    if min_date < PRESENT_DATE or max_date > PRESENT_DATE:
        mock_update.assert_called_with(
            table=mock_table,
            md5='',
            query='',
            min_date=min_date if min_date < PRESENT_DATE else PRESENT_DATE,
            max_date=max_date if max_date > PRESENT_DATE else PRESENT_DATE,
        )
    else:
        mock_update.assert_not_called()


@patch('azure_utils.logging.error')
@patch('db.orm.get_row', side_effect=AttributeError)
def test_update_row_object_ko(mock_get, mock_logging):
    """Test update_row_object handles ORM errors as expected."""
    with pytest.raises(SystemExit) as err:
        update_row_object(table=MagicMock(__tablename__=''), md5_hash=None, new_min=None, new_max=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure_utils.logging.error')
@patch('db.orm.update_row', side_effect=orm.AzureORMError)
@patch(
    'db.orm.get_row',
    return_value=MagicMock(min_processed_date=PRESENT_DATE, max_processed_date=PRESENT_DATE),
)
def test_update_row_object_ko_update(mock_get, mock_update, mock_logging):
    """Test update_row_object handles ORM errors as expected."""
    with pytest.raises(SystemExit) as err:
        update_row_object(
            table=MagicMock(__tablename__=''),
            md5_hash=None,
            new_min=PAST_DATE,
            new_max=FUTURE_DATE,
        )
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('db.orm.add_row')
def test_create_new_row(add_row):
    """Test create_new_row invokes the ORM functionality with a valid row object."""
    mock_table = MagicMock(__tablename__='')
    item = create_new_row(table=mock_table, md5_hash='hash', query='query', offset=None)
    datetime_str = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).strftime(DATETIME_MASK)
    mock_table.assert_called_with(
        md5='hash',
        query='query',
        min_processed_date=datetime_str,
        max_processed_date=datetime_str,
    )
    add_row.assert_called_with(row=item)


@patch('azure_utils.logging.error')
@patch('db.orm.add_row', side_effect=orm.AzureORMError)
def test_create_new_row_ko(mock_add_row, mock_logging):
    """Test create_new_row raises an error if when attempting to add a invalid row object."""
    with pytest.raises(SystemExit) as err:
        create_new_row(
            table=MagicMock(__tablename__=''),
            md5_hash='hash',
            query='query',
            offset=None,
        )
    assert err.value.code == 1
    mock_logging.assert_called_once()
