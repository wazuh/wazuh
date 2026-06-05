# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3
import aws_tools
import services

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
      '--external_id', utils.TEST_EXTERNAL_ID, '--queue', utils.TEST_SQS_NAME], 'subscribers.sqs_queue.AWSSQSQueue'),
    (['main', '--subscriber', 'buckets', '--queue', utils.TEST_SQS_NAME], 'subscribers.sqs_queue.AWSSQSQueue'),
    (['main', '--subscriber', 'security_hub', '--queue', utils.TEST_SQS_NAME], 'subscribers.sqs_queue.AWSSQSQueue')
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
        if args[2] == 'inspector':
            total_regions = len(services.inspector.INSPECTOR_V1_REGIONS) + len(services.inspector.INSPECTOR_V2_REGIONS)
            assert mocked_class.call_count == total_regions
            assert instance.get_alerts.call_count == total_regions
        else:
            assert mocked_class.call_count == len(aws_tools.ALL_REGIONS)
            assert instance.get_alerts.call_count == len(aws_tools.ALL_REGIONS)
    elif 'subscriber' in args[1]:
        mocked_class.assert_called_once()
        instance.sync_events.assert_called_once()


@pytest.mark.parametrize('args, error_code', [
    (['main', '--bucket', 'bucket-name', '--type', 'invalid'], utils.INVALID_TYPE_ERROR_CODE),
    (['main', '--service', 'invalid'], utils.INVALID_TYPE_ERROR_CODE),
    (['main', '--subscriber', 'invalid'], utils.INVALID_TYPE_ERROR_CODE),
    (['main', '--service', 'cloudwatchlogs', '--regions', 'in-valid-1'], utils.INVALID_REGION_ERROR_CODE),
    (['main', '--service', 'inspector', '--regions', 'in-valid-1'], utils.INVALID_REGION_ERROR_CODE),
    (['main', '--service', 'inspector', '--regions', 'in-valid-8'], utils.INVALID_REGION_ERROR_CODE)
])
def test_main_type_ko(args: list[str], error_code: int):
    """Test 'main' function handles exceptions when receiving invalid buckets or services.

    Parameters
    ----------
    args : list[str]
        List of arguments that make the `main` function exit.
    error_code : int
        Expected error code.
    """
    with patch("sys.argv", args), \
            pytest.raises(SystemExit) as e:
        aws_s3.main(args)
    assert e.value.code == error_code


def test_main_sets_debug_level_when_debug_flag_provided():
    """main() sets aws_tools.debug_level and logs a debug message when --debug > 0."""
    args = ['main', '--bucket', 'bucket-name', '--type', 'cloudtrail', '--debug', '2']
    instance = MagicMock()
    with patch("sys.argv", args), \
            patch("configparser.RawConfigParser.has_option", return_value=False), \
            patch('buckets_s3.cloudtrail.AWSCloudTrailBucket') as mocked_class, \
            patch.object(aws_tools, 'debug') as mock_debug:
        mocked_class.return_value = instance
        aws_s3.main(args)
    assert aws_tools.debug_level == 2
    mock_debug.assert_any_call('+++ Debug mode on - Level: 2', 1)


def test_main_exits_22_on_invalid_bucket_region():
    """main() exits with code 22 when a region passes format validation but is not in ALL_REGIONS."""
    # zz-fake-1 matches the regex in arg_valid_regions but is not in aws_tools.ALL_REGIONS
    args = ['main', '--bucket', 'bucket-name', '--type', 'cloudtrail', '--regions', 'zz-fake-1']
    with patch("sys.argv", args), \
            pytest.raises(SystemExit) as e:
        aws_s3.main(args)
    assert e.value.code == 22


def test_main_appends_region_from_aws_config_when_no_regions_specified():
    """main() appends the region from the AWS config profile when no --regions are given."""
    args = ['main', '--service', 'cloudwatchlogs']
    instance = MagicMock()
    with patch("sys.argv", args), \
            patch("configparser.RawConfigParser.has_option", return_value=True), \
            patch("configparser.RawConfigParser.get", return_value="us-east-1"), \
            patch('services.cloudwatchlogs.AWSCloudWatchLogs') as mocked_class:
        mocked_class.return_value = instance
        aws_s3.main(args)
    mocked_class.assert_called_once()
    assert mocked_class.call_args.kwargs['region'] == 'us-east-1'


def test_main_reraises_exception_in_debug_mode():
    """main() re-raises exceptions inside the except block when debug_level > 0."""
    args = ['main', '--bucket', 'bucket-name', '--type', 'cloudtrail', '--debug', '1']
    aws_tools.debug_level = 1
    instance = MagicMock()
    instance.check_bucket.side_effect = RuntimeError("forced error")
    with patch("sys.argv", args), \
            patch("configparser.RawConfigParser.has_option", return_value=False), \
            patch('buckets_s3.cloudtrail.AWSCloudTrailBucket') as mocked_class:
        mocked_class.return_value = instance
        with pytest.raises(RuntimeError, match="forced error"):
            aws_s3.main(args)
    aws_tools.debug_level = 0


def test_main_block_success():
    """__main__ block registers SIGINT handler and exits 0 on success."""
    import runpy
    import signal as signal_mod
    aws_s3_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', 'aws_s3.py'))
    mock_opts = MagicMock(debug='0', logBucket=None, service=None, subscriber=None)
    with patch('aws_tools.get_script_arguments', return_value=mock_opts), \
            patch('signal.signal') as mock_signal, \
            pytest.raises(SystemExit) as e:
        runpy.run_path(aws_s3_path, run_name='__main__')
    assert e.value.code == 0
    mock_signal.assert_called_once_with(signal_mod.SIGINT, aws_tools.handler)


def test_main_block_exits_1_on_exception():
    """__main__ block calls aws_tools.error and exits 1 on unhandled exception."""
    import runpy
    aws_s3_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', 'aws_s3.py'))
    with patch('aws_tools.get_script_arguments', side_effect=Exception("boom")), \
            patch('aws_tools.error') as mock_error, \
            pytest.raises(SystemExit) as e:
        runpy.run_path(aws_s3_path, run_name='__main__')
    assert e.value.code == 1
    mock_error.assert_called_once_with("Unknown error: boom")


def test_main_block_reraises_when_debug_level_gt_0():
    """__main__ block re-raises the exception when aws_tools.debug_level > 0."""
    import runpy
    aws_s3_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', 'aws_s3.py'))
    aws_tools.debug_level = 1
    try:
        with patch('aws_tools.get_script_arguments', side_effect=Exception("boom")), \
                patch('aws_tools.error'), \
                pytest.raises(Exception, match="boom"):
            runpy.run_path(aws_s3_path, run_name='__main__')
    finally:
        aws_tools.debug_level = 0
