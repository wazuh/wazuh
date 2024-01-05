# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import configparser

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3
import aws_tools

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils


@pytest.mark.parametrize('args, class_', [
    (['main', '--bucket', 'bucket-name', '--type', 'cloudtrail'], 'buckets_s3.cloudtrail.AWSCloudTrailBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'vpcflow'], 'buckets_s3.vpcflow.AWSVPCFlowBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'config'], 'buckets_s3.config.AWSConfigBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'custom'], 'buckets_s3.aws_bucket.AWSCustomBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'guardduty'], 'buckets_s3.guardduty.AWSGuardDutyBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'cisco_umbrella'], 'buckets_s3.umbrella.CiscoUmbrella'),
    (['main', '--bucket', 'bucket-name', '--type', 'waf'], 'buckets_s3.waf.AWSWAFBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'alb'], 'buckets_s3.load_balancers.AWSALBBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'clb'], 'buckets_s3.load_balancers.AWSCLBBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'nlb'], 'buckets_s3.load_balancers.AWSNLBBucket'),
    (['main', '--bucket', 'bucket-name', '--type', 'server_access'], 'buckets_s3.server_access.AWSServerAccess'),
    (['main', '--service', 'inspector'], 'services.inspector.AWSInspector'),
    (['main', '--service', 'cloudwatchlogs'], 'services.cloudwatchlogs.AWSCloudWatchLogs'),
    (['main', '--subscriber', 'security_lake', '--iam_role_arn', utils.TEST_IAM_ROLE_ARN,
      '--external_id', utils.TEST_EXTERNAL_ID, '--queue', utils.TEST_SQS_NAME], 'subscribers.sqs_queue.AWSSQSQueue')
])
@patch('aws_tools.get_script_arguments', side_effect=aws_tools.get_script_arguments)
def test_main(mock_arguments, args: list[str], class_):
    """Test 'main' function makes the expected calls when processing buckets or services.

    Parameters
    ----------
    args : list[str]
        List of arguments that make the `main` function exit.
    class_: AWSBucket or AWSService
        Class to be instantiated.
    """
    instance = MagicMock()
    with patch("sys.argv", args), \
            patch("configparser.RawConfigParser.has_option", return_value=False), \
            patch(class_) as mocked_class:
        mocked_class.return_value = instance
        aws_s3.main(args)
    mock_arguments.assert_called_once()
    if 'bucket' in args[1]:
        mocked_class.assert_called_once()
        instance.check_bucket.assert_called_once()
        instance.iter_bucket.assert_called_once()
    elif 'service' in args[1]:
        assert mocked_class.call_count == len(aws_tools.ALL_REGIONS)
        assert instance.get_alerts.call_count == len(aws_tools.ALL_REGIONS)
    elif 'subscriber' in args[1]:
        mocked_class.assert_called_once()
        instance.sync_events.assert_called_once()


@pytest.mark.parametrize('args', [
    ['main', '--bucket', 'bucket-name', '--type', 'invalid'],
    ['main', '--service', 'invalid'],
    ['main', '--subscriber', 'invalid']
])
@patch('aws_tools.get_script_arguments', side_effect=aws_tools.get_script_arguments)
def test_main_type_ko(mock_arguments, args: list[str]):
    """Test 'main' function handles exceptions when receiving invalid buckets or services.

    Parameters
    ----------
    args : list[str]
        List of arguments that make the `main` function exit.
    """
    with patch("sys.argv", args), \
            pytest.raises(SystemExit) as e:
        aws_s3.main(args)
    assert e.value.code == utils.INVALID_TYPE_ERROR_CODE


@patch('aws_tools.get_script_arguments', side_effect=aws_tools.get_script_arguments)
def test_main_invalid_region_ko(mock_arguments):
    """Test 'main' function handles exceptions when receiving invalid region.

    Parameters
    ----------
    args : list[str]
        List of arguments that make the `main` function exit.
    """
    args = ['main', '--service', 'inspector', '--regions', 'in-valid-1']

    with patch("sys.argv", args), \
            pytest.raises(SystemExit) as e:
        aws_s3.main(args)
    assert e.value.code == utils.INVALID_REGION_ERROR_CODE
