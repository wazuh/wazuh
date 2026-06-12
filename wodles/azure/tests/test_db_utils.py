# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest azure/tests/test_db_utils.py -v --log-cli-level=DEBUG

import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from db import utils as db_utils
from db.orm import AzureORMError

logger = logging.getLogger(__name__)

OLD_MIN = '2021-01-01T00:00:00.000000Z'
OLD_MAX = '2021-01-31T00:00:00.000000Z'
MD5_HASH = 'abc123md5hash'


@pytest.fixture
def mock_table():
    table = MagicMock()
    table.__tablename__ = 'log_analytics'
    return table


@pytest.fixture
def mock_row():
    row = MagicMock()
    row.min_processed_date = OLD_MIN
    row.max_processed_date = OLD_MAX
    return row


class TestUpdateRowObject:
    def test_updates_when_new_min_is_earlier(self, mock_table, mock_row):
        new_min = '2020-12-01T00:00:00.000000Z'
        with patch.object(db_utils.orm, 'get_row', return_value=mock_row), \
             patch.object(db_utils.orm, 'update_row') as mock_update:
            db_utils.update_row_object(mock_table, MD5_HASH, new_min, OLD_MAX)
            logger.info(f"update_row called with min={new_min}, max={OLD_MAX}")
            mock_update.assert_called_once_with(
                table=mock_table, md5=MD5_HASH, min_date=new_min, max_date=OLD_MAX, query=None
            )

    def test_updates_when_new_max_is_later(self, mock_table, mock_row):
        new_max = '2021-02-15T00:00:00.000000Z'
        with patch.object(db_utils.orm, 'get_row', return_value=mock_row), \
             patch.object(db_utils.orm, 'update_row') as mock_update:
            db_utils.update_row_object(mock_table, MD5_HASH, OLD_MIN, new_max)
            logger.info(f"update_row called with max={new_max}")
            mock_update.assert_called_once()

    def test_does_not_update_when_dates_within_range(self, mock_table, mock_row):
        new_min = '2021-01-15T00:00:00.000000Z'
        new_max = '2021-01-20T00:00:00.000000Z'
        with patch.object(db_utils.orm, 'get_row', return_value=mock_row), \
             patch.object(db_utils.orm, 'update_row') as mock_update:
            db_utils.update_row_object(mock_table, MD5_HASH, new_min, new_max)
            logger.info("update_row NOT called (dates within stored range)")
            mock_update.assert_not_called()

    def test_exits_on_get_row_orm_error(self, mock_table):
        with patch.object(db_utils.orm, 'get_row', side_effect=AzureORMError('db error')):
            with pytest.raises(SystemExit) as exc_info:
                db_utils.update_row_object(mock_table, MD5_HASH, OLD_MIN, OLD_MAX)
            logger.info(f"SystemExit code on get_row error => {exc_info.value.code}")
            assert exc_info.value.code == 1

    def test_exits_on_update_row_orm_error(self, mock_table, mock_row):
        new_min = '2020-01-01T00:00:00.000000Z'  # earlier → triggers update path
        with patch.object(db_utils.orm, 'get_row', return_value=mock_row), \
             patch.object(db_utils.orm, 'update_row', side_effect=AzureORMError('update error')):
            with pytest.raises(SystemExit) as exc_info:
                db_utils.update_row_object(mock_table, MD5_HASH, new_min, OLD_MAX)
            logger.info(f"SystemExit code on update_row error => {exc_info.value.code}")
            assert exc_info.value.code == 1

    def test_passes_query_parameter_to_update_row(self, mock_table, mock_row):
        new_min = '2020-01-01T00:00:00.000000Z'
        with patch.object(db_utils.orm, 'get_row', return_value=mock_row), \
             patch.object(db_utils.orm, 'update_row') as mock_update:
            db_utils.update_row_object(mock_table, MD5_HASH, new_min, OLD_MAX, query='SELECT *')
            logger.info(f"update_row query kwarg => {mock_update.call_args.kwargs.get('query')}")
            assert mock_update.call_args.kwargs['query'] == 'SELECT *'


class TestCreateNewRow:
    def test_adds_row_and_returns_it(self, mock_table):
        mock_item = MagicMock()
        mock_table.return_value = mock_item
        with patch.object(db_utils.orm, 'add_row') as mock_add:
            result = db_utils.create_new_row(mock_table, MD5_HASH, query='SELECT *', offset='1d')
            logger.info(f"create_new_row result is mock_item => {result is mock_item}")
            mock_add.assert_called_once_with(row=mock_item)
            assert result is mock_item

    def test_uses_offset_to_datetime_when_offset_provided(self, mock_table):
        from datetime import datetime
        fixed_dt = datetime(2021, 6, 1, 0, 0, 0)
        mock_table.return_value = MagicMock()
        with patch.object(db_utils.orm, 'add_row'), \
             patch('db.utils.offset_to_datetime', return_value=fixed_dt) as mock_offset:
            db_utils.create_new_row(mock_table, MD5_HASH, query='q', offset='7d')
            logger.info(f"offset_to_datetime called with => {mock_offset.call_args}")
            mock_offset.assert_called_once_with('7d')

    def test_does_not_call_offset_to_datetime_when_no_offset(self, mock_table):
        mock_table.return_value = MagicMock()
        with patch.object(db_utils.orm, 'add_row'), \
             patch('db.utils.offset_to_datetime') as mock_offset:
            db_utils.create_new_row(mock_table, MD5_HASH, query='q', offset=None)
            logger.info("No offset => offset_to_datetime NOT called")
            mock_offset.assert_not_called()

    def test_exits_on_add_row_orm_error(self, mock_table):
        mock_table.return_value = MagicMock()
        with patch.object(db_utils.orm, 'add_row', side_effect=AzureORMError('insert error')):
            with pytest.raises(SystemExit) as exc_info:
                db_utils.create_new_row(mock_table, MD5_HASH, query='q', offset=None)
            logger.info(f"SystemExit code on add_row error => {exc_info.value.code}")
            assert exc_info.value.code == 1
