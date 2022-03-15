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
import pytest
from unittest.mock import patch
from logging import Logger

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
import exceptions
from buckets.bucket import WazuhGCloudBucket


def test_get_bucket(gcloud_bucket: WazuhGCloudBucket):
    """Check if an instance of WazuhGCloudBucket is created properly."""
    expected_attributes = ['bucket_name', 'bucket', 'client', 'project_id',
                           'prefix', 'delete_file', 'only_logs_after',
                           'db_connector', 'datetime_format']

    assert isinstance(gcloud_bucket, WazuhGCloudBucket)

    for attribute in expected_attributes:
        assert hasattr(gcloud_bucket, attribute)


@pytest.mark.parametrize('credentials_file,logger,bucket_name,exception,errcode', [
    ('unexistent_file',
     None,
     'test_bucket', exceptions.GCloudError, 1001),
    ('invalid_credentials_file.json',
     None,
     'test_bucket',
     exceptions.GCloudError, 1000)
])
def test_bucket_ko(credentials_file: str, logger: Logger,
                   bucket_name: str, exception: exceptions.WazuhIntegrationException,
                   test_data_path: str, errcode: int):
    """
    Check that the appropriate exceptions are raised
    when the WazuhGCloudBucket constructor is called with
    wrong parameters.

    Parameters
    ----------
    credentials_file : str
        File with the GCP credentials.
    logger : Logger
        Logger used to capture the output of the module.
    bucket_name : str
        Name of the bucket.
    exception : exceptions.WazuhIntegrationException
        Exception that should be raised by the module.
    test_data_path : str
        Path where the data folder is.
    errcode : int
        Error code of the exception raised.
    """
    with pytest.raises(exception) as e:
        WazuhGCloudBucket(credentials_file=test_data_path + credentials_file,
                          logger=logger, bucket_name=bucket_name)
    assert e.value.errcode == errcode
