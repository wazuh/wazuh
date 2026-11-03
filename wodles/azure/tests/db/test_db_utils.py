#!/usr/bin/env python3
#
# Copyright (C) Wazuh Inc.
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
from db.utils import (
    create_new_row,
    get_ingestion_cursor,
    get_processed_bytes,
    lower_max_processed_date,
    remove_stale_offsets,
    save_processed_bytes,
    update_ingestion_cursor,
    update_row_object,
)

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


@pytest.mark.parametrize(
    'row, expected',
    [
        (None, None),
        (MagicMock(creation_time='t1', processed_bytes=10), 10),
        # The blob was created again after storing its offset
        (MagicMock(creation_time='t0', processed_bytes=10), 0),
    ],
)
@patch('db.orm.get_blob_offset')
def test_get_processed_bytes(mock_get, row, expected):
    """Test get_processed_bytes returns the stored offset only if it belongs to the same blob."""
    mock_get.return_value = row
    assert get_processed_bytes(md5_hash='hash', container='container', blob='blob', creation_time='t1') == expected
    mock_get.assert_called_with(md5='hash', container='container', blob='blob')


@patch('db.orm.delete_stale_blob_offsets')
@patch('db.orm.set_blob_offset')
def test_save_and_remove_offsets(mock_set, mock_delete):
    """Test the blob offset functions invoke the ORM functionality with the given values."""
    save_processed_bytes(md5_hash='hash', container='container', blob='blob', creation_time='t1', processed_bytes=20)
    mock_set.assert_called_with(md5='hash', container='container', blob='blob', creation_time='t1', processed_bytes=20)

    remove_stale_offsets(md5_hash='hash', container='container', prefix='prefix', keep={'blob'})
    mock_delete.assert_called_with(md5='hash', container='container', prefix='prefix', keep={'blob'})


@pytest.mark.parametrize(
    'function, args',
    [
        (get_processed_bytes, ('hash', 'container', 'blob', 't1')),
        (save_processed_bytes, ('hash', 'container', 'blob', 't1', 1)),
        (remove_stale_offsets, ('hash', 'container', None, set())),
    ],
)
@patch('azure_utils.logging.error')
@patch('db.orm.delete_stale_blob_offsets', side_effect=orm.AzureORMError)
@patch('db.orm.set_blob_offset', side_effect=orm.AzureORMError)
@patch('db.orm.get_blob_offset', side_effect=orm.AzureORMError)
def test_blob_offset_functions_ko(mock_get, mock_set, mock_delete, mock_logging, function, args):
    """Test the blob offset functions handle ORM errors as expected."""
    with pytest.raises(SystemExit) as err:
        function(*args)
    assert err.value.code == 1
    mock_logging.assert_called_once()


IT_1 = '2026-10-07T08:42:43.6877773Z'
IT_2 = '2026-10-07T08:45:55.7365454Z'
TG_1 = '2026-10-07T08:40:20.5975486Z'
TG_2 = '2026-10-07T08:40:20.7185586Z'
IT_TRIMMED, IT_PADDED = '2026-10-07T08:41:46.5Z', '2026-10-07T08:41:46.5000001Z'
TG_TRIMMED, TG_PADDED = '2026-10-07T08:40:20.5Z', '2026-10-07T08:40:20.5000001Z'


@pytest.mark.parametrize(
    'stored, ingestion_times, times, expected',
    [
        (None, [], [], None),
        (None, [None, None], [TG_1, TG_2], None),
        (None, [IT_1, IT_2, None], [TG_2, TG_1, TG_2], (IT_2, TG_1)),
        # Records ingested at the same time are sorted by TimeGenerated
        (None, [IT_1, IT_1], [TG_2, TG_1], (IT_1, TG_2)),
        ((IT_1, TG_1), [IT_1], [TG_2], (IT_1, TG_2)),
        # An earlier record doesn't move back the one stored
        ((IT_2, TG_1), [IT_1], [TG_2], None),
        ((IT_1, TG_2), [IT_1], [TG_1], None),
        ((IT_1, TG_2), [IT_1], [TG_2], None),
        # Azure trims the trailing zeros of the fraction
        ((IT_TRIMMED, TG_1), [IT_PADDED], [TG_1], (IT_PADDED, TG_1)),
        ((IT_PADDED, TG_1), [IT_TRIMMED, '2026-10-07T08:41:46Z'], [TG_2, TG_2], None),
        ((IT_1, TG_TRIMMED), [IT_1], [TG_PADDED], (IT_1, TG_PADDED)),
    ],
)
@patch('db.orm.set_ingestion_cursor')
@patch('db.orm.get_ingestion_cursor')
def test_update_ingestion_cursor(mock_get, mock_set, stored, ingestion_times, times, expected):
    """Test update_ingestion_cursor only stores the last record, by ingestion time and TimeGenerated, if it's after
    the one stored."""
    mock_get.return_value = MagicMock(ingestion_time=stored[0], time_generated=stored[1]) if stored else None
    update_ingestion_cursor(md5_hash='hash', ingestion_times=ingestion_times, times=times)
    if expected:
        mock_set.assert_called_once_with(md5='hash', ingestion_time=expected[0], time_generated=expected[1])
    else:
        mock_set.assert_not_called()


@pytest.mark.parametrize(
    'row, expected', [(None, None), (MagicMock(ingestion_time=IT_1, time_generated=TG_1), (IT_1, TG_1))]
)
@patch('db.orm.get_ingestion_cursor')
def test_get_ingestion_cursor(mock_get, row, expected):
    """Test get_ingestion_cursor returns the ingestion time and TimeGenerated stored for the query."""
    mock_get.return_value = row
    assert get_ingestion_cursor(md5_hash='hash') == expected
    mock_get.assert_called_once_with(md5='hash')


@pytest.mark.parametrize(
    'function, args',
    [
        (get_ingestion_cursor, ('hash',)),
        (update_ingestion_cursor, ('hash', [IT_1], [TG_1])),
    ],
)
@patch('azure_utils.logging.error')
@patch('db.orm.set_ingestion_cursor', side_effect=orm.AzureORMError)
@patch('db.orm.get_ingestion_cursor', side_effect=orm.AzureORMError)
def test_ingestion_cursor_functions_ko(mock_get, mock_set, mock_logging, function, args):
    """Test the ingestion cursor functions handle ORM errors as expected."""
    with pytest.raises(SystemExit) as err:
        function(*args)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize(
    'stored_max, max_date, expected',
    [
        # A newest date stored ahead of the query time is lowered to it
        ('2026-10-08T10:00:00.0000000Z', '2026-10-07T10:15:00.1234567Z', '2026-10-07T10:15:00.1234567Z'),
        ('2026-10-07T10:00:00Z', '2026-10-07T10:15:00Z', None),
        ('2026-10-07T10:15:00Z', '2026-10-07T10:15:00Z', None),
    ],
)
@patch('db.orm.update_row')
@patch('db.orm.get_row')
def test_lower_max_processed_date(mock_get, mock_update, stored_max, max_date, expected):
    """Test lower_max_processed_date only replaces the newest date stored when it's later than the given one."""
    mock_get.return_value = MagicMock(min_processed_date=PAST_DATE, max_processed_date=stored_max)
    lower_max_processed_date(table=orm.LogAnalytics, md5_hash='hash', max_date=max_date)
    mock_get.assert_called_once_with(table=orm.LogAnalytics, md5='hash')
    if expected:
        mock_update.assert_called_once_with(table=orm.LogAnalytics, md5='hash', min_date=PAST_DATE, max_date=expected)
    else:
        mock_update.assert_not_called()


@pytest.mark.parametrize('get_error, update_error', [(True, False), (False, True)])
@patch('azure_utils.logging.error')
@patch('db.orm.update_row')
@patch('db.orm.get_row')
def test_lower_max_processed_date_ko(mock_get, mock_update, mock_logging, get_error, update_error):
    """Test lower_max_processed_date handles ORM errors as expected."""
    mock_get.return_value = MagicMock(min_processed_date=PAST_DATE, max_processed_date=FUTURE_DATE)
    if get_error:
        mock_get.side_effect = orm.AzureORMError
    if update_error:
        mock_update.side_effect = orm.AzureORMError
    with pytest.raises(SystemExit) as err:
        lower_max_processed_date(table=orm.LogAnalytics, md5_hash='hash', max_date=PRESENT_DATE)
    assert err.value.code == 1
    mock_logging.assert_called_once()
