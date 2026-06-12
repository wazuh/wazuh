# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest gcloud/tests/test_access_logs.py -v --log-cli-level=DEBUG

import logging
import os
import sys
from logging import Logger
from unittest.mock import MagicMock, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from buckets.access_logs import GCSAccessLogs

logger = logging.getLogger(__name__)


@pytest.fixture
def access_logs_instance():
    """Create a GCSAccessLogs instance with the parent __init__ mocked out."""
    parent_cls = GCSAccessLogs.__bases__[0]
    with patch.object(parent_cls, '__init__', return_value=None):
        return GCSAccessLogs(
            credentials_file='fake_creds.json',
            logger=MagicMock(spec=Logger),
            bucket_name='test-bucket',
            prefix='',
        )


def test_db_table_name_is_access_logs(access_logs_instance):
    logger.info(f"db_table_name => {access_logs_instance.db_table_name}")
    assert access_logs_instance.db_table_name == 'access_logs'


def test_load_information_parses_csv_lines(access_logs_instance):
    msg = '"time_micros","c_ip","c_ip_type"\n"123456","1.2.3.4","1"\n"789012","5.6.7.8","1"'
    result = access_logs_instance.load_information_from_file(msg)
    logger.info(f"load_information_from_file result => {result}")
    assert len(result) == 2
    assert result[0]['time_micros'] == '123456'
    assert result[1]['c_ip'] == '5.6.7.8'


def test_load_information_adds_source_field(access_logs_instance):
    msg = '"field_a","field_b"\n"val1","val2"'
    result = access_logs_instance.load_information_from_file(msg)
    logger.info(f"source field => {result[0].get('source')}")
    assert result[0]['source'] == 'gcp_bucket'


def test_load_information_strips_quotes_from_fieldnames(access_logs_instance):
    msg = '"col_one","col_two"\n"alpha","beta"'
    result = access_logs_instance.load_information_from_file(msg)
    logger.info(f"fieldnames => {list(result[0].keys())}")
    assert 'col_one' in result[0]
    assert 'col_two' in result[0]


def test_load_information_does_not_raise_on_empty_data_lines(access_logs_instance):
    """Function should not raise when there are no data rows after the header."""
    msg = '"field_a","field_b"\n'
    result = access_logs_instance.load_information_from_file(msg)
    logger.info(f"empty data result => {result}")
    assert isinstance(result, list)


def test_load_information_multiple_rows_all_have_source(access_logs_instance):
    msg = '"a","b"\n"1","2"\n"3","4"\n"5","6"'
    result = access_logs_instance.load_information_from_file(msg)
    logger.info(f"all rows have source => {[r['source'] for r in result]}")
    assert all(r['source'] == 'gcp_bucket' for r in result)
    assert len(result) == 3
