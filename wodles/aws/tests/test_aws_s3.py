import argparse
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

import aws_s3

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils


@pytest.mark.parametrize('msg_level', range(3))
@patch('builtins.print')
def test_debug(mock_print, msg_level):
    """Test 'debug' function only prints messages with a level equal or greater than the debug level."""
    msg = "test message"
    aws_s3.debug(msg, msg_level)
    if aws_s3.debug_level >= msg_level:
        mock_print.assert_called_with(f"DEBUG: {msg}")
    else:
        mock_print.assert_not_called()


def test_arg_valid_date():
    """Test 'arg_valid_date' function returns a string with the expected format."""
    parsed_date = aws_s3.arg_valid_date("2022-JAN-01")
    assert isinstance(parsed_date, str)
    assert parsed_date == "20220101"


def test_arg_valid_date_ko():
    """Test 'arg_valid_date' function raises an 'ArgumentTypeError' error if the format provided is not supported."""
    with pytest.raises(argparse.ArgumentTypeError):
        aws_s3.arg_valid_date("2022-01-01")


@pytest.mark.parametrize('arg_string', ['prefix', 'prefix/', None])
def test_arg_valid_prefix(arg_string):
    prefix = aws_s3.arg_valid_prefix(arg_string)
    if arg_string:
        assert isinstance(prefix, str)
        assert prefix[-1] == "/"
        assert arg_string in prefix


@pytest.mark.parametrize('arg_string', [
    utils.TEST_ACCOUNT_ID,
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID}',
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID}',
    None
])
def test_arg_valid_accountid(arg_string):
    account_ids = aws_s3.arg_valid_accountid(arg_string)
    assert isinstance(account_ids, list)
    assert len(account_ids) == (len(arg_string.split(',')) if arg_string else 0)


@pytest.mark.parametrize('arg_string', [
    utils.TEST_ACCOUNT_ID[:-1],
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID[:-1]}',
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID},123456789abc'
])
def test_arg_valid_accountid_ko(arg_string):
    with pytest.raises(argparse.ArgumentTypeError):
        aws_s3.arg_valid_accountid(arg_string)


@pytest.mark.parametrize('arg_string', [
    utils.TEST_REGION,
    f'{utils.TEST_REGION},{utils.TEST_REGION}',
    f'{utils.TEST_REGION},{utils.TEST_REGION},{utils.TEST_REGION}',
    None
])
def test_arg_valid_regions(arg_string):
    regions = aws_s3.arg_valid_regions(arg_string)
    assert isinstance(regions, list)
    assert len(regions) == (len(arg_string.split(',')) if arg_string else 0)


@pytest.mark.parametrize('arg_string', ["900", "3600"])
def test_arg_valid_iam_role_duration(arg_string):
    duration = aws_s3.arg_valid_iam_role_duration(arg_string)
    assert isinstance(duration, int)
    assert duration == int(arg_string)


@pytest.mark.parametrize('arg_string', ["899", "3601"])
def test_arg_valid_iam_role_duration_ko(arg_string):
    with pytest.raises(argparse.ArgumentTypeError):
        aws_s3.arg_valid_iam_role_duration(arg_string)


@patch('configparser.RawConfigParser')
def test_get_aws_config_params(mock_config):
    config = MagicMock()
    mock_config.return_value = config
    assert aws_s3.get_aws_config_params() == config
    config.read.assert_called_with(aws_s3.DEFAULT_AWS_CONFIG_PATH)


@pytest.mark.parametrize('mutually_exclusive_parameter', ['--bucket', '--service'])
def test_get_script_arguments(capsys, mutually_exclusive_parameter):
    """Test 'get_script_arguments' function shows no messages when the required parameters were provided."""
    with patch("sys.argv", ['main', mutually_exclusive_parameter, 'any']):
        aws_s3.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'stdout was not empty'
    assert stderr == "", 'stderr was not empty'


@pytest.mark.parametrize('args', [
    ['main'],
])
def test_get_script_arguments_required(capsys, args):
    """Test 'get_script_arguments' function shows an error message when the required parameters are not provided."""
    with patch("sys.argv", args), pytest.raises(SystemExit) as exception:
        aws_s3.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'The output was not empty'
    assert stderr != "", 'No error message was found in the output'
    assert exception.value.code == 2


@pytest.mark.parametrize('args, class_', [
    (['main', '--bucket', 'bucket_name', '--type', 'cloudtrail'], 'buckets_s3.cloudtrail.AWSCloudTrailBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'vpcflow'], 'buckets_s3.vpcflow.AWSVPCFlowBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'config'], 'buckets_s3.config.AWSConfigBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'custom'], 'buckets_s3.aws_bucket.AWSCustomBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'guardduty'], 'buckets_s3.guardduty.AWSGuardDutyBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'cisco_umbrella'], 'buckets_s3.umbrella.CiscoUmbrella'),
    (['main', '--bucket', 'bucket_name', '--type', 'waf'], 'buckets_s3.waf.AWSWAFBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'alb'], 'buckets_s3.load_balancers.AWSALBBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'clb'], 'buckets_s3.load_balancers.AWSCLBBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'nlb'], 'buckets_s3.load_balancers.AWSNLBBucket'),
    (['main', '--bucket', 'bucket_name', '--type', 'server_access'], 'buckets_s3.server_access.AWSServerAccess'),
    (['main', '--service', 'inspector'], 'services.inspector.AWSInspector'),
    (['main', '--service', 'cloudwatchlogs'], 'services.cloudwatchlogs.AWSCloudWatchLogs')
])
@patch('aws_s3.get_script_arguments', side_effect=aws_s3.get_script_arguments)
def test_main(mock_arguments, args, class_):
    instance = MagicMock()
    with patch("sys.argv", args), \
            patch(class_) as mocked_class:
        mocked_class.return_value = instance
        aws_s3.main(args)
    mock_arguments.assert_called_once()
    if 'bucket' in args[1]:
        mocked_class.assert_called_once()
        instance.check_bucket.assert_called_once()
        instance.iter_bucket.assert_called_once()
    elif 'service' in args[1]:
        assert mocked_class.call_count == len(aws_s3.ALL_REGIONS)
        assert instance.get_alerts.call_count == len(aws_s3.ALL_REGIONS)


@pytest.mark.parametrize('args', [
    ['main', '--bucket', 'bucket_name', '--type', 'invalid'],
    ['main', '--service', 'invalid']
])
@patch('aws_s3.get_script_arguments', side_effect=aws_s3.get_script_arguments)
def test_main_ko(mock_arguments, args):
    with patch("sys.argv", args), \
        pytest.raises(SystemExit) as e:
        aws_s3.main(args)
    assert e.value.code == utils.INVALID_TYPE_ERROR_CODE
