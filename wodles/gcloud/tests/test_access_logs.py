#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for access_logs module."""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from buckets.access_logs import GCSAccessLogs

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

credentials_file = 'credentials.json'
logger = None
f_kwargs = {"bucket_name": 'test-bucket',
            "prefix": "",
            "delete_file": False,
            "only_logs_after": None}

@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def get_GCSAccessLogs(mock_client):
    """Return a WazuhGCloudSubscriber client."""
    client = GCSAccessLogs(credentials_file, logger, **f_kwargs)
    return client


def test_get_access_logs():
    """Check if an instance of WazuhGCloudBucket is created properly."""
    expected_attributes = ['db_table_name', 'bucket_name', 'bucket', 'client', 'project_id', 'prefix', 'delete_file',
                           'only_logs_after', 'db_connector', 'datetime_format']

    client = get_GCSAccessLogs()

    assert isinstance(client, GCSAccessLogs)

    for attribute in expected_attributes:
        assert hasattr(client, attribute)
