# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
import botocore.exceptions
from unittest.mock import patch, MagicMock

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import waf

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_path = os.path.join(test_data_path, 'log_files')


@patch('aws_bucket.AWSCustomBucket.__init__', autospec=True)
def test_aws_waf_bucket_initializes_properly(mock_custom_bucket):
    """Test if the instances of AWSWAFBucket are created properly."""
    with patch('waf.AWSWAFBucket.check_waf_type'):
        utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
        mock_custom_bucket.assert_called_once()


@pytest.mark.parametrize('log_file, skip_on_error', [
    (os.path.join(logs_path, 'WAF', 'aws-waf'), False),
    (os.path.join(logs_path, 'WAF', 'aws-waf'), True),
    (os.path.join(logs_path, 'WAF', 'aws-waf-invalid-json'), True),
    (os.path.join(logs_path, 'WAF', 'aws-waf-wrong-structure'), True),
])
@patch('aws_bucket.AWSCustomBucket.__init__', autospec=True)
@patch('aws_bucket.AWSBucket.__init__', autospec=True)
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_waf_bucket_load_information_from_file(mock_db, mock_integration, mock_sts, mock_bucket, log_file, skip_on_error):
    """Test that verifies if the AWSWAFBucket load_information_from_file method raises an exception with invalid arguments.

    Parameters
    ----------
    log_file: str
        File that should be decompressed.
    skip_on_error: bool
        Whether the skip_on_error option is enabled or not.
    expected_exception: Exception
        The expected exception that should be raised.
    """
    with patch('waf.AWSWAFBucket.check_waf_type'):
        instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
        instance.bucket = "test-bucket"
        instance.skip_on_error = skip_on_error
        with open(log_file, 'rb') as f:
            instance.client = MagicMock()
            instance.client.get_object.return_value.__getitem__.return_value = f
            instance.load_information_from_file(log_file)


@pytest.mark.parametrize('log_file, skip_on_error, expected_exception', [
    (os.path.join(logs_path, 'WAF', 'aws-waf-invalid-json'), False, SystemExit),
    (os.path.join(logs_path, 'WAF', 'aws-waf-wrong-structure'), False, SystemExit),
])
@patch('aws_bucket.AWSCustomBucket.__init__', autospec=True)
@patch('aws_bucket.AWSBucket.__init__', autospec=True)
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_waf_bucket_load_information_from_file_handles_exception_on_invalid_argument(
        mock_db, mock_integration, mock_sts, mock_bucket, log_file, skip_on_error, expected_exception):
    """Test that verifies if the AWSWAFBucket load_information_from_file method works correctly.

    Parameters
    ----------
    log_file: str
        File that should be decompressed.
    skip_on_error: bool
        Whether the skip_on_error option is enabled or not.
    """
    with patch('waf.AWSWAFBucket.check_waf_type'):
        instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
        instance.bucket = "test-bucket"  # Ensure the bucket attribute is set
        instance.skip_on_error = skip_on_error
        with open(log_file, 'rb') as f:
            instance.client = MagicMock()
            instance.client.get_object.return_value.__getitem__.return_value = f
            with pytest.raises(expected_exception):
                instance.load_information_from_file(log_file)


@pytest.mark.parametrize('object_list, result', [(utils.LIST_OBJECT_V2, True),
                                                 (utils.LIST_OBJECT_V2_NO_PREFIXES, False)])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_waf_bucket_check_waf_type(mock_wazuh_aws_integration, mock_sts,
                                                   object_list: dict, result: bool):
    """Test 'check_waf_type' method defines if the bucket contains WAF Native logs or not.

    Parameters
    ----------
    object_list: dict
        Objects to be returned by list_objects_v2.
    result: bool
        Expected result.
    """
    with patch('waf.AWSWAFBucket.check_waf_type'):
        instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)

    instance.client = MagicMock()
    instance.client.list_objects_v2.return_value = object_list

    assert result == instance.check_waf_type()


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_waf_bucket_check_waf_type_handles_exceptions(mock_wazuh_aws_integration, mock_sts):
    """Test 'check_waf_type' handles exceptions raised and exits with the expected exit code."""
    with patch('waf.AWSWAFBucket.check_waf_type'):
        instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)

    with pytest.raises(SystemExit) as e:
        instance.client = MagicMock()
        instance.client.list_objects_v2.side_effect = Exception
        instance.check_waf_type()
    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3


@patch('aws_bucket.AWSLogsBucket.get_base_prefix', return_value='base_prefix/')
@patch('waf.AWSWAFBucket.check_waf_type')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_aws_waf_bucket_get_service_prefix(mock_custom_bucket, mock_type, mock_base_prefix):
    """Test 'get_service_prefix' method returns the expected prefix with the format
    <base_prefix>/<account_id>/<service>."""
    instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)

    expected_base_prefix = os.path.join('base_prefix', utils.TEST_ACCOUNT_ID, instance.service, '')
    assert instance.get_service_prefix(utils.TEST_ACCOUNT_ID) == expected_base_prefix


@pytest.mark.parametrize('waf_native', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_waf_bucket_get_base_prefix(mock_wazuh_aws_integration, mock_sts, waf_native: bool):
    """Test 'get_full_prefix' method the expected base prefix depending on the WAF bucket type.

    Parameters
    ----------
    waf_native: bool
        Result for the 'check_waf_type' call that determines the GuardDuty bucket type.
    """
    with patch('waf.AWSWAFBucket.check_waf_type', return_value=waf_native):
        instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket, prefix='prefix/')

        if instance.type == "WAFNative":
            assert instance.get_base_prefix() == os.path.join(instance.prefix, 'AWSLogs', '')
        else:
            assert instance.get_base_prefix() == instance.prefix


@pytest.mark.parametrize('waf_native', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_waf_bucket_iter_regions_and_accounts(mock_wazuh_aws_integration, mock_sts, waf_native: bool):
    """Test 'iter_regions_and_accounts' method makes the necessary calls in order to process the bucket's files
    depending on the WAF bucket type.
    
    Parameters
    ----------
    waf_native: bool
        Result for the 'check_waf_type' call that determines the WAF bucket type.
    """
    account_ids = [utils.TEST_ACCOUNT_ID]
    regions = [utils.TEST_REGION]
    
    with patch('waf.AWSWAFBucket.check_waf_type', return_value=waf_native), \
            patch('aws_bucket.AWSBucket.iter_regions_and_accounts') as mock_bucket_regions_and_accounts, \
            patch('aws_bucket.AWSCustomBucket.iter_regions_and_accounts') as mock_custom_regions_and_accounts:
        instance = utils.get_mocked_bucket(class_=waf.AWSWAFBucket)
        
        if waf_native:
            with pytest.raises(SystemExit) as excinfo:
                instance.iter_regions_and_accounts(account_ids, regions)
            assert excinfo.value.code == 9
            mock_bucket_regions_and_accounts.assert_not_called()
        else:
            instance.iter_regions_and_accounts(account_ids, regions)
            assert instance.check_prefix
            mock_custom_regions_and_accounts.assert_called_with(instance, account_ids, regions)
