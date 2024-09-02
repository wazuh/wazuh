# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
import copy
from unittest.mock import patch, MagicMock
import re
from datetime import datetime

import wodles.aws.tests.aws_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils
import aws_constants as test_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import config

TEST_CONFIG_SCHEMA = "schema_config_test.sql"
TEST_TABLE_NAME = 'config'

TEST_DATE = '2023/1/1'
DAYS_DELTA = 10

SQL_FIND_LAST_LOG_PROCESSED = """SELECT created_date FROM {table_name} ORDER BY created_date DESC LIMIT 1;"""
SQL_FIND_LAST_KEY_PROCESSED = """SELECT log_key FROM {table_name} ORDER BY log_key DESC LIMIT 1;"""

test_constants.LIST_OBJECT_V2_NO_PREFIXES['Contents'][0]['Key'] = test_constants.TEST_LOG_FULL_PATH_CONFIG_1


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_aws_config_bucket_initializes_properly(mock_logs_bucket):
    """Test if the instances of AWSConfigBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    mock_logs_bucket.assert_called_once()
    assert instance.service == "Config"
    assert instance.field_to_load == "configurationItems"
    assert instance._leading_zero_regex == re.compile(r'/(0)(?P<num>\d)')
    assert instance._extract_date_regex == re.compile(r'\d{4}/\d{1,2}/\d{1,2}')


@pytest.mark.parametrize('marker, result_marker', [
    ('AWSLogs/123456789012/Config/us-east-1/2020/01/06', 'AWSLogs/123456789012/Config/us-east-1/2020/1/6'),
    ('AWSLogs/123456789/Config/us-east-1/2019/04/15/', 'AWSLogs/123456789/Config/us-east-1/2019/4/15/'),
    ('AWSLogs/123456789/Config/us-east-1/2019/12/06/', 'AWSLogs/123456789/Config/us-east-1/2019/12/6/')
])
@patch('aws_bucket.AWSBucket.marker_only_logs_after')
def test_aws_config_bucket_marker_only_logs_after(mock_marker_only_logs_after, marker: str, result_marker: str):
    """Test 'marker_only_logs_after' method returns the expected marker.

    Parameters
    ----------
    marker: str
        The marker introduced.
    result_marker: str
        The marker the method should return without padding zeros in the date.
    """
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket, only_logs_after=test_constants.TEST_ONLY_LOGS_AFTER)
    mock_marker_only_logs_after.return_value = result_marker

    assert instance.marker_only_logs_after(test_constants.TEST_ACCOUNT_ID,
                                           test_constants.TEST_REGION) == instance._remove_padding_zeros_from_marker(marker)


@patch('aws_bucket.AWSBucket.marker_only_logs_after')
def test_aws_config_bucket_marker_only_logs_after_handles_exceptions(mock_marker_only_logs_after):
    """Test 'marker_only_logs_after' method handles the AtrributeError exception and exits
    with the expected exit code."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    mock_marker_only_logs_after.return_value = os.path.join('AWSLogs', '123456789', 'Config', 'us-east-1', '2019', '12',
                                                            '06')

    with patch('re.sub') as mock_re_sub:
        with pytest.raises(SystemExit) as e:
            mock_re_sub.side_effect = AttributeError
            instance.marker_only_logs_after(test_constants.TEST_ACCOUNT_ID,
                                            test_constants.TEST_REGION)

        assert e.value.code == wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE


@patch('aws_bucket.AWSBucket.marker_custom_date')
def test_aws_config_bucket_marker_custom_date(mock_marker_custom_date):
    """Test 'marker_custom_date' method returns the expected marker when specifying a custom date."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    custom_date = datetime(2022, 9, 8)

    mock_marker_custom_date.return_value = os.path.join('AWSLogs', test_constants.TEST_ACCOUNT_ID, 'Config',
                                                        test_constants.TEST_REGION,
                                                        custom_date.strftime(instance.date_format))

    assert instance.marker_custom_date(test_constants.TEST_ACCOUNT_ID,
                                       test_constants.TEST_REGION,
                                       custom_date) == instance._remove_padding_zeros_from_marker(
        mock_marker_custom_date(instance, test_constants.TEST_ACCOUNT_ID,
                                test_constants.TEST_REGION, custom_date))


@pytest.mark.parametrize('security_groups', ['securityGroupId', [{'groupId': 'id', 'groupName': 'name'}],
                                             {'groupId': 'id', 'groupName': 'name'}])
@pytest.mark.parametrize('availability_zones',
                         ['zone', [{'subnetId': 'id', 'zoneName': 'name'}], {'subnetId': 'id', 'zoneName': 'name'}])
@pytest.mark.parametrize('state', ['stateName', {}])
@pytest.mark.parametrize('created_time', [1672763065, '2020-06-01T01:03:03.106Z'])
@pytest.mark.parametrize('iam_profile', ['iamInstanceProfileName', {}])
@patch('aws_bucket.AWSBucket.reformat_msg')
def test_aws_config_bucket_reformat_msg(mock_reformat,
                                        iam_profile: str or dict, created_time: int or str, state: str or dict,
                                        availability_zones: str or dict, security_groups: str or dict):
    """Test 'reformat_msg' method applies the expected format to a given event.

    Parameters
    ----------
    iam_profile: str or dict
        IAM instance profile.
    created_time: int or str
        Event creation time.
    state: str or dict
        State values for the state key.
    availability_zones: str or dict
        Availability zones values for the availabilityZones key.
    security_groups: str or dict
        Security groups values for the securityGroups key.
    """
    event = copy.deepcopy(constants.AWS_BUCKET_MSG_TEMPLATE)
    event['aws'].update(
        {
            'configuration': {
                'securityGroups': security_groups,
                'availabilityZones': availability_zones,
                'state': state,
                'createdTime': created_time,
                'iamInstanceProfile': iam_profile,
                'unnecesary_fields': {
                    'Content': {
                        'example_key': 'example_value'
                    }
                }
            }
        }
    )

    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)

    formatted_event = instance.reformat_msg(event)

    assert isinstance(formatted_event['aws']['configuration']['securityGroups'], dict)
    assert isinstance(formatted_event['aws']['configuration']['availabilityZones'], dict)
    assert isinstance(formatted_event['aws']['configuration']['state'], dict)
    assert isinstance(formatted_event['aws']['configuration']['createdTime'], float)
    assert isinstance(formatted_event['aws']['configuration']['iamInstanceProfile'], dict)
    assert isinstance(formatted_event['aws']['configuration']['unnecesary_fields']['Content'], list)
