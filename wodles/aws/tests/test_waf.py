# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import waf

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_path = os.path.join(test_data_path, 'log_files')


@patch('aws_bucket.AWSCustomBucket.__init__')
def test_aws_waf_bucket_initializes_properly(mock_custom_bucket):
    """Test if the instances of AWSWAFBucket are created properly."""
    utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
    mock_custom_bucket.assert_called_once()


@pytest.mark.parametrize('log_file, skip_on_error', [
    (os.path.join(logs_path, 'WAF', 'aws-waf'), False),
    (os.path.join(logs_path, 'WAF', 'aws-waf'), True),
    (os.path.join(logs_path, 'WAF', 'aws-waf-invalid-json'), True),
    (os.path.join(logs_path, 'WAF', 'aws-waf-wrong-structure'), True),
])
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
@patch('aws_bucket.AWSCustomBucket.__init__', side_effect=aws_bucket.AWSCustomBucket.__init__)
def test_aws_waf_bucket_load_information_from_file(mock_custom_bucket, mock_bucket, mock_sts, mock_integration,
                                                   log_file: str, skip_on_error: bool):
    """Test AWSWAFBucket's implementation of the load_information_from_file method.

    Parameters
    ----------
    log_file : str
        File that should be decompressed.
    skip_on_error : bool
        If the skip_on_error is disabled or not.
    """
    instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
    instance.skip_on_error = skip_on_error
    with open(log_file, 'rb') as f:
        instance.client = MagicMock()
        instance.client.get_object.return_value.__getitem__.return_value = f
        instance.load_information_from_file(log_file)


@pytest.mark.parametrize('log_file, skip_on_error, expected_exception', [
    (os.path.join(logs_path, 'WAF', 'aws-waf-invalid-json'), False, SystemExit),
    (os.path.join(logs_path, 'WAF', 'aws-waf-wrong-structure'), False, SystemExit),
])
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
@patch('aws_bucket.AWSCustomBucket.__init__', side_effect=aws_bucket.AWSCustomBucket.__init__)
def test_aws_waf_bucket_load_information_from_file_handles_exception_on_invalid_argument(mock_custom_bucket,
                                                                                         mock_bucket, mock_sts,
                                                                                         mock_integration,
                                                                                         log_file: str,
                                                                                         skip_on_error: bool,
                                                                                         expected_exception: Exception):
    """Test that AWSWAFBucket's implementation of the load_information_from_file method raises
    an exception when called with invalid arguments.

    Parameters
    ----------
    log_file : str
        File that should be decompressed.
    skip_on_error : bool
        If the skip_on_error is disabled or not.
    expected_exception : Exception
        Exception that should be raised.
    """
    instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
    instance.skip_on_error = skip_on_error
    with open(log_file, 'rb') as f, \
            pytest.raises(expected_exception):
        instance.client = MagicMock()
        instance.client.get_object.return_value.__getitem__.return_value = f
        instance.load_information_from_file(log_file)
