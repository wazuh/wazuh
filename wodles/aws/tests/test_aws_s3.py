import argparse
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

import aws_s3
import aws_tools

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils


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


@pytest.mark.parametrize('args', [
    ['main', '--bucket', 'bucket_name', '--type', 'invalid'],
    ['main', '--service', 'invalid']
])
@patch('aws_tools.get_script_arguments', side_effect=aws_tools.get_script_arguments)
def test_main_ko(mock_arguments, args: list[str]):
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
