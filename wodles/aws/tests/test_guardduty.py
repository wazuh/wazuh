# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
import copy
from unittest.mock import patch, mock_open, MagicMock

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import guardduty

SAMPLE_EVENT_1 = {'key1': 'value1', 'key2': 'value2'}


@pytest.mark.parametrize('guardduty_native', [True, False])
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_aws_guardduty_bucket_initializes_properly(mock_custom_bucket, guardduty_native):
    """Test if the instances of AWSGuardDutyBucket are created properly."""
    with patch('guardduty.AWSGuardDutyBucket.check_guardduty_type', return_value=guardduty_native):
        instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)

        mock_custom_bucket.assert_called_once()
        assert instance.service == "GuardDuty"

        if guardduty_native:
            assert instance.type == "GuardDutyNative"
        else:
            assert instance.type == "GuardDutyKinesis"


@pytest.mark.parametrize('object_list, result', [(utils.LIST_OBJECT_V2, True),
                                                 (utils.LIST_OBJECT_V2_NO_PREFIXES, False)])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_guardduty_bucket_check_guardduty_type(mock_wazuh_aws_integration, mock_sts,
                                                   object_list: dict, result: bool):
    """Test 'check_guardduty_type' method defines if the bucket contains GuardDuty Native logs or not.

    Parameters
    ----------
    object_list: dict
        Objects to be returned by list_objects_v2.
    result: bool
        Expected result.
    """
    with patch('guardduty.AWSGuardDutyBucket.check_guardduty_type'):
        instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)

    instance.client = MagicMock()
    instance.client.list_objects_v2.return_value = object_list

    assert result == instance.check_guardduty_type()


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_guardduty_bucket_check_guardduty_type_handles_exceptions(mock_wazuh_aws_integration, mock_sts):
    """Test 'check_guardduty_type' handles exceptions raised and exits with the expected exit code."""
    with patch('guardduty.AWSGuardDutyBucket.check_guardduty_type'):
        instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)

    with pytest.raises(SystemExit) as e:
        instance.client = MagicMock()
        instance.client.list_objects_v2.side_effect = Exception
        instance.check_guardduty_type()
    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3


@patch('aws_bucket.AWSLogsBucket.get_base_prefix', return_value='base_prefix/')
@patch('guardduty.AWSGuardDutyBucket.check_guardduty_type')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_aws_guardduty_bucket_get_service_prefix(mock_custom_bucket, mock_type, mock_base_prefix):
    """Test 'get_service_prefix' method returns the expected prefix with the format
    <base_prefix>/<account_id>/<service>."""
    instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)

    expected_base_prefix = os.path.join('base_prefix', utils.TEST_ACCOUNT_ID, instance.service, '')
    assert instance.get_service_prefix(utils.TEST_ACCOUNT_ID) == expected_base_prefix


@pytest.mark.parametrize('guardduty_native', [True, False])
@patch('aws_bucket.AWSLogsBucket.get_service_prefix', return_value='service_prefix/')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_guardduty_bucket_get_full_prefix(mock_wazuh_aws_integration, mock_sts, mock_service_prefix,
                                              guardduty_native):
    """Test 'get_full_prefix' method the expected prefix depending on the GuardDuty bucket type.

    Parameters
    ----------
    guardduty_native: bool
        Result for the 'check_guardduty_type' call that determines the GuardDuty bucket type.
    """
    with patch('guardduty.AWSGuardDutyBucket.check_guardduty_type', return_value=guardduty_native):
        instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket, prefix='prefix/')

        if instance.type == "GuardDutyNative":
            assert os.path.join(instance.get_service_prefix(utils.TEST_ACCOUNT_ID), utils.TEST_REGION, '') == \
                   instance.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
        else:
            assert instance.prefix == instance.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)


@pytest.mark.parametrize('guardduty_native', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_guardduty_bucket_get_base_prefix(mock_wazuh_aws_integration, mock_sts, guardduty_native: bool):
    """Test 'get_full_prefix' method the expected base prefix depending on the GuardDuty bucket type.

    Parameters
    ----------
    guardduty_native: bool
        Result for the 'check_guardduty_type' call that determines the GuardDuty bucket type.
    """
    with patch('guardduty.AWSGuardDutyBucket.check_guardduty_type', return_value=guardduty_native):
        instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket, prefix='prefix/')

        if instance.type == "GuardDutyNative":
            assert instance.get_base_prefix() == os.path.join(instance.prefix, 'AWSLogs', '')
        else:
            assert instance.get_base_prefix() == instance.prefix


@pytest.mark.parametrize('guardduty_native', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_guardduty_bucket_iter_regions_and_accounts(mock_wazuh_aws_integration, mock_sts, guardduty_native: bool):
    """Test 'iter_regions_and_accounts' method makes the necessary calls in order to process the bucket's files
    depending on the GuardDuty bucket type.

    Parameters
    ----------
    guardduty_native: bool
        Result for the 'check_guardduty_type' call that determines the GuardDuty bucket type.
    """
    account_ids = [utils.TEST_ACCOUNT_ID]
    regions = [utils.TEST_REGION]
    with patch('guardduty.AWSGuardDutyBucket.check_guardduty_type', return_value=guardduty_native), \
            patch('aws_bucket.AWSBucket.iter_regions_and_accounts') as mock_bucket_regions_and_accounts, \
            patch('aws_bucket.AWSCustomBucket.iter_regions_and_accounts') as mock_custom_regions_and_accounts:
        instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)

        if instance.type == "GuardDutyNative":
            instance.iter_regions_and_accounts(account_ids, regions)
            mock_bucket_regions_and_accounts.assert_called_with(instance, account_ids, regions)
        else:
            instance.iter_regions_and_accounts(account_ids, regions)
            assert instance.check_prefix
            mock_custom_regions_and_accounts.assert_called_with(instance, account_ids, regions)


@patch('guardduty.AWSGuardDutyBucket.send_msg')
@patch('guardduty.AWSGuardDutyBucket.reformat_msg', return_value=['message'])
@patch('guardduty.AWSGuardDutyBucket.check_guardduty_type')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_aws_guardduty_bucket_send_event(mock_custom_bucket, mock_type, mock_reformat, mock_send):
    """Test 'send_event' method makes the necessary calls in order to send the event to Analysisd."""
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)
    instance.send_event(event)
    mock_reformat.assert_called_with(event)
    mock_send.assert_called()


@pytest.mark.parametrize('fields', [{
    'service':
        {'action':
            {
                'portProbeAction':
                    {
                        'portProbeDetails': [
                            {
                                "localIpDetails": {
                                    "ipAddressV4": "string"
                                },
                                "localPortDetails": {
                                    "port": "number",
                                    "portName": "string"
                                }
                            },
                            {
                                "localIpDetails": {
                                    "ipAddressV4": "string"
                                },
                                "localPortDetails": {
                                    "port": "number",
                                    "portName": "string"
                                }
                            }]
                    }}},
    'additional_field': ['element']
}, {'otherField': 'element'}])
@patch('aws_bucket.AWSBucket.reformat_msg')
@patch('guardduty.AWSGuardDutyBucket.check_guardduty_type')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_aws_guardduty_bucket_reformat_msg(mock_custom_bucket, mock_type, mock_reformat, fields: dict):
    """Test 'reformat_msg' method applies the expected format to a given event..

    Parameters
    ----------
    fields: dict
        Dictionary part of the event to be reformatted.
    """
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    event['aws'].update({'source': 'guardduty'})
    event['aws'].update(fields)
    instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)
    result = []

    formatted_event = list(instance.reformat_msg(event))

    if 'service' in event['aws'] and \
            'action' in event['aws']['service'] and \
            'portProbeAction' in event['aws']['service']['action'] and \
            'portProbeDetails' in event['aws']['service']['action']['portProbeAction'] and \
            len(event['aws']['service']['action']['portProbeAction']['portProbeDetails']) > 1:
        port_probe_details = event['aws']['service']['action']['portProbeAction']['portProbeDetails']
        for detail in port_probe_details:
            event['aws']['service']['action']['portProbeAction']['portProbeDetails'] = detail
            result.append(event)
        assert result == formatted_event

    else:
        mock_reformat.assert_called_once()
        assert [event] == formatted_event


@pytest.mark.parametrize('log_key, json_file_content, result',
                         [('file.jsonl.gz',
                           '{"detail": {"schemaVersion": "2.0"}, "service": {"serviceName": "guardduty"}}',
                           [{"detail": {"schemaVersion": "2.0"}, "service": {"serviceName": "guardduty"},
                             "source": "guardduty"}]),
                          ('file.zip',
                           '{"source": "guardduty", "detail": {"schemaVersion": "2.0"}}',
                           [{"source": "guardduty", "schemaVersion": "2.0"}])])
@patch('aws_bucket.AWSBucket.decompress_file')
@patch('guardduty.AWSGuardDutyBucket.check_guardduty_type')
@patch('aws_bucket.AWSCustomBucket.get_sts_client')
def test_aws_guardduty_bucket_load_information_from_file(mock_sts_client, mock_type, mock_decompress,
                                                         log_key: str, json_file_content: list[dict] or str,
                                                         result: list[dict]):
    """Test 'load_information_from_file' method returns the expected information.

    Parameters
    ----------
    log_key: str
        Name of the file to be processed.
    json_file_content: str
        File content.
    result: list[dict]
        Expected information to be fetched from the file.
    """
    instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)
    with patch('aws_bucket.AWSBucket.decompress_file', mock_open(read_data=json_file_content)):
        assert result == instance.load_information_from_file(log_key)
