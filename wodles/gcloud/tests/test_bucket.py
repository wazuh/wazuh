#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for bucket module."""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from buckets.bucket import WazuhGCloudBucket

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

credentials_file = 'credentials.json'
logger = None
bucket_name = 'test-bucket'
prefix = ""
delete_file = False
only_logs_after = None


@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def get_WazuhGCloudBucket(mock_client):
    """Return a WazuhGCloudSubscriber client."""
    client = WazuhGCloudBucket(credentials_file, logger, bucket_name, prefix, delete_file, only_logs_after)
    return client


def test_get_bucket():
    """Check if an instance of WazuhGCloudBucket is created properly."""
    expected_attributes = ['bucket_name', 'bucket', 'client', 'project_id', 'prefix', 'delete_file', 'only_logs_after',
                           'db_connector', 'datetime_format']

    client = get_WazuhGCloudBucket()

    assert isinstance(client, WazuhGCloudBucket)

    for attribute in expected_attributes:
        assert hasattr(client, attribute)
