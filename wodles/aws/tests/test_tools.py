# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import sys
import io
from unittest.mock import MagicMock, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_tools

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils


@pytest.mark.parametrize('msg_level', range(3))
@patch('builtins.print')
def test_debug(mock_print, msg_level):
    """Test 'debug' function only prints messages with a level equal or greater than the debug level."""
    msg = "test message"
    aws_tools.debug(msg, msg_level)
    if aws_tools.debug_level >= msg_level:
        mock_print.assert_called_with(f"DEBUG: {msg}")
    else:
        mock_print.assert_not_called()


def test_arg_valid_date():
    """Test 'arg_valid_date' function returns a string with the expected format."""
    parsed_date = aws_tools.arg_valid_date("2022-JAN-01")
    assert isinstance(parsed_date, str)
    assert parsed_date == "20220101"


def test_arg_valid_date_raises_exception_when_invalid_format_provided():
    """Test 'arg_valid_date' function raises an 'ArgumentTypeError' error if the format provided is not supported."""
    with pytest.raises(argparse.ArgumentTypeError):
        aws_tools.arg_valid_date("2022-01-01")


@pytest.mark.parametrize('arg_string', ['prefix', 'prefix/', ''])
def test_arg_valid_key(arg_string: str):
    """Test 'arg_valid_key' function returns the expected key.

    Parameters
    ----------
    arg_string: str
        String containing the key to be formatted.
    """
    prefix = aws_tools.arg_valid_key(arg_string)
    if arg_string:
        assert isinstance(prefix, str)
        assert prefix[-1] == "/"
        assert arg_string in prefix


def test_arg_valid_key_raises_exception_when_invalid_format_provided():
    """Test 'arg_valid_key' function raises an 'ArgumentTypeError' error when invalid key is provided."""
    with pytest.raises(argparse.ArgumentTypeError) as e:
        aws_tools.arg_valid_key('prefix{}')


@pytest.mark.parametrize('arg_string', [
    utils.TEST_ACCOUNT_ID,
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID}',
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID}',
    None
])
def test_arg_valid_accountid(arg_string: str or None):
    """Test 'arg_valid_accountid' function returns the expected number of account IDs.

    Parameters
    ----------
    arg_string: str or None
        String of account ids separated by comma.
    """
    account_ids = aws_tools.arg_valid_accountid(arg_string)
    assert isinstance(account_ids, list)
    assert len(account_ids) == (len(arg_string.split(',')) if arg_string else 0)


@pytest.mark.parametrize('arg_string', [
    utils.TEST_ACCOUNT_ID[:-1],
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID[:-1]}',
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID},123456789abc'
])
def test_arg_valid_accountid_raises_exception_when_invalid_account_provided(arg_string):
    """Test 'arg_valid_accountid' function raises an 'ArgumentTypeError' error
    if the number of digits is different to 12 or the account id is not formed only by digits.

    Parameters
    ----------
    arg_string: str or None
        String of account ids separated by comma.
    """
    with pytest.raises(argparse.ArgumentTypeError):
        aws_tools.arg_valid_accountid(arg_string)


@pytest.mark.parametrize('arg_string', [
    utils.TEST_REGION,
    f'{utils.TEST_REGION},{utils.TEST_REGION}',
    f'{utils.TEST_REGION},{utils.TEST_REGION},{utils.TEST_REGION}',
    None
])
def test_arg_valid_regions(arg_string):
    """Test 'arg_valid_regions' function returns the expected number of regions.

    Parameters
    ----------
    arg_string: str or None
        String of regions separated by comma.
    """
    regions = aws_tools.arg_valid_regions(arg_string)
    assert isinstance(regions, list)
    assert len(regions) == (len(set(arg_string.split(','))) if arg_string else 0)


def test_arg_valid_regions_raises_exception_when_invalid_region_provided():
    """Test 'arg_valid_regions' function raises an 'ArgumentTypeError' error when invalid region is provided."""
    with pytest.raises(argparse.ArgumentTypeError) as e:
        aws_tools.arg_valid_regions('invalid-region')


@pytest.mark.parametrize('arg_string', ["900", "3600"])
def test_arg_valid_iam_role_duration(arg_string: str):
    """Test 'arg_valid_iam_role_duration' function returns the expected duration.

    Parameters
    ----------
    arg_string: str
        The desired session duration in seconds.
    """
    duration = aws_tools.arg_valid_iam_role_duration(arg_string)
    assert isinstance(duration, int)
    assert duration == int(arg_string)


def test_arg_valid_bucket_name_raises_exception_when_invalid_bucket_name_provided():
    """Test 'arg_valid_bucket_name' function raises an 'ArgumentTypeError' error when invalid
    bucket name is provided.
    """
    with pytest.raises(argparse.ArgumentTypeError) as e:
        aws_tools.arg_valid_bucket_name('--ol-s3-invalid')


@pytest.mark.parametrize('arg_string', ["899", "3601"])
def test_arg_valid_iam_role_duration_raises_exception_when_invalid_duration_provided(arg_string):
    """Test 'arg_valid_iam_role_duration' function raises an 'ArgumentTypeError' error
    when the duration is not between 15m and 12h.

    Parameters
    ----------
    arg_string: str
        The desired session duration in seconds.
    """
    with pytest.raises(argparse.ArgumentTypeError):
        aws_tools.arg_valid_iam_role_duration(arg_string)


@pytest.mark.parametrize("test_input, expected_output", [
    (('external_id', None, None, 'default'), "ERROR: Used a subscriber but no --iam_role_arn provided."),
    (('external_id', None, 'iam_role_arn', 'default'), "ERROR: Used a subscriber but no --queue provided."),
    ((None, 'name', 'iam_role_arn', 'default'), "ERROR: Used a subscriber but no --external_id provided.")
])
def test_arg_validate_security_lake_auth_params(test_input, expected_output):
    """Test the arg_validate_security_lake_auth_params function of aws_tools."""
    captured_output = io.StringIO()
    sys.stdout = captured_output

    with pytest.raises(SystemExit) as excinfo:
        aws_tools.arg_validate_security_lake_auth_params(*test_input)

    output = captured_output.getvalue().strip()

    assert output == expected_output
    assert excinfo.value.code == 21

    sys.stdout = sys.__stdout__


@patch('configparser.RawConfigParser')
def test_get_aws_config_params(mock_config):
    """Test 'get_aws_config_params' function returns the expected configparser.RawConfigParser object"""
    config = MagicMock()
    mock_config.return_value = config
    assert aws_tools.get_aws_config_params() == config
    config.read.assert_called_with(aws_tools.DEFAULT_AWS_CONFIG_PATH)


@pytest.mark.parametrize('mutually_exclusive_parameter', ['--bucket', '--service'])
def test_get_script_arguments(capsys, mutually_exclusive_parameter):
    """Test 'get_script_arguments' function shows no messages when the required parameters were provided."""
    with patch("sys.argv", ['main', mutually_exclusive_parameter, 'any']):
        aws_tools.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'stdout was not empty'
    assert stderr == "", 'stderr was not empty'


@pytest.mark.parametrize('args', [
    ['main'],
])
def test_get_script_arguments_required(capsys, args):
    """Test 'get_script_arguments' function shows an error message when the required parameters are not provided."""
    with patch("sys.argv", args), pytest.raises(SystemExit) as exception:
        aws_tools.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'The output was not empty'
    assert stderr != "", 'No error message was found in the output'
    assert exception.value.code == 2


def test_get_script_arguments_iam_role_duration_but_no_iam_role_arn_raises_exception():
    """Test 'get_script_arguments' function raises an 'ArgumentTypeError' error when the `iam_role_duration`
    parameter is provided but the 'iam_role_arn' is not.
    """
    args = ['main', '--subscriber', 'security_lake', '--iam_role_duration', '3600']
    with patch("sys.argv", args), pytest.raises(argparse.ArgumentTypeError) as exception:
        aws_tools.get_script_arguments()


# ---------------------------------------------------------------------------
# handler
# ---------------------------------------------------------------------------

def test_handler_exits_with_code_2():
    """handler() prints an error message and exits with code 2 on SIGINT."""
    with patch('builtins.print') as mock_print, pytest.raises(SystemExit) as exc_info:
        aws_tools.handler(None, None)
    assert exc_info.value.code == 2
    mock_print.assert_called_once_with("ERROR: SIGINT received.")


# ---------------------------------------------------------------------------
# set_profile_dict_config
# ---------------------------------------------------------------------------

def test_set_profile_dict_config_sets_s3_config_when_profile_has_s3_section():
    """set_profile_dict_config sets boto_config['config'].s3 when the profile has an s3 section."""
    from botocore.config import Config
    boto_config = {'config': Config()}
    profile = 'myprofile'
    profile_config = {
        f'{profile}.s3.max_concurrent_requests': '5',
        f'{profile}.s3.max_queue_size': '8',
        f'{profile}.s3.multipart_threshold': '16MB',
        f'{profile}.s3.multipart_chunksize': '16MB',
        f'{profile}.s3.max_bandwidth': None,
        f'{profile}.s3.use_accelerate_endpoint': 'true',
        f'{profile}.s3.addressing_style': 'path',
    }

    mock_config = MagicMock()
    mock_config.__contains__ = lambda self, key: key in str(profile_config)

    def mock_get(key, default=None):
        return profile_config.get(key, default)

    mock_config.get = mock_get
    mock_config.__str__ = lambda self: str(profile_config)

    aws_tools.set_profile_dict_config(boto_config, profile, mock_config)

    s3 = boto_config['config'].s3
    assert s3['max_concurrent_requests'] == 5
    assert s3['max_queue_size'] == 8
    assert s3['multipart_threshold'] == '16MB'
    assert s3['use_accelerate_endpoint'] is True
    assert s3['addressing_style'] == 'path'


def test_set_profile_dict_config_sets_proxy_config_when_profile_has_proxy_section():
    """set_profile_dict_config sets proxies and proxies_config when the profile has a proxy section."""
    from botocore.config import Config
    boto_config = {'config': Config()}
    profile = 'myprofile'
    profile_config = {
        f'{profile}.proxy.host': 'proxy.example.com',
        f'{profile}.proxy.port': '8080',
        f'{profile}.proxy.username': 'user',
        f'{profile}.proxy.password': 'pass',
        f'{profile}.proxy.ca_bundle': '/etc/ssl/ca.pem',
        f'{profile}.proxy.client_cert': '/etc/ssl/client.pem',
        f'{profile}.proxy.use_forwarding_for_https': 'true',
    }

    mock_config = MagicMock()
    mock_config.__str__ = lambda self: str(profile_config)

    def mock_get(key, default=None):
        return profile_config.get(key, default)

    mock_config.get = mock_get

    aws_tools.set_profile_dict_config(boto_config, profile, mock_config)

    proxies = boto_config['config'].proxies
    assert proxies['host'] == 'proxy.example.com'
    assert proxies['port'] == 8080
    assert proxies['username'] == 'user'

    proxies_config = boto_config['config'].proxies_config
    assert proxies_config['ca_bundle'] == '/etc/ssl/ca.pem'
    assert proxies_config['use_forwarding_for_https'] is True


def test_set_profile_dict_config_strips_profile_prefix():
    """set_profile_dict_config strips the 'profile ' prefix from the profile name before lookups."""
    from botocore.config import Config
    boto_config = {'config': Config()}
    # Profile name with 'profile ' prefix as it appears in some AWS config files
    profile_with_prefix = 'profile myprofile'
    stripped = 'myprofile'
    profile_config_data = {
        f'{stripped}.s3.max_concurrent_requests': '3',
        f'{stripped}.s3.max_queue_size': '3',
        f'{stripped}.s3.use_accelerate_endpoint': 'false',
        f'{stripped}.s3.addressing_style': 'auto',
    }

    mock_config = MagicMock()
    mock_config.__str__ = lambda self: str(profile_config_data)

    def mock_get(key, default=None):
        return profile_config_data.get(key, default)

    mock_config.get = mock_get

    aws_tools.set_profile_dict_config(boto_config, profile_with_prefix, mock_config)

    assert boto_config['config'].s3['addressing_style'] == 'auto'


def test_set_profile_dict_config_does_not_set_s3_or_proxy_when_absent():
    """set_profile_dict_config leaves boto_config unchanged when neither s3 nor proxy sections exist."""
    from botocore.config import Config
    cfg = Config()
    boto_config = {'config': cfg}

    mock_config = MagicMock()
    mock_config.__str__ = lambda self: '{}'

    aws_tools.set_profile_dict_config(boto_config, 'myprofile', mock_config)

    assert boto_config['config'].s3 is None
    assert boto_config['config'].proxies is None
