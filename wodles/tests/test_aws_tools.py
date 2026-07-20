# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_aws_tools.py -v --log-cli-level=DEBUG

import argparse
import logging
import os
import sys
from unittest.mock import patch

import pytest

logger = logging.getLogger(__name__)

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'aws'))
import aws_tools


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_default_aws_config_path():
    """DEFAULT_AWS_CONFIG_PATH must point to ~/.aws/config."""
    logger.info("DEFAULT_AWS_CONFIG_PATH => %r", aws_tools.DEFAULT_AWS_CONFIG_PATH)
    assert aws_tools.DEFAULT_AWS_CONFIG_PATH.endswith(os.path.join('.aws', 'config'))


def test_all_regions_is_tuple():
    """ALL_REGIONS must be a tuple of non-empty strings."""
    logger.info("ALL_REGIONS count => %d", len(aws_tools.ALL_REGIONS))
    assert isinstance(aws_tools.ALL_REGIONS, tuple)
    assert all(isinstance(r, str) and r for r in aws_tools.ALL_REGIONS)


def test_debug_level_default():
    """debug_level must default to 0."""
    logger.info("debug_level => %d", aws_tools.debug_level)
    assert aws_tools.debug_level == 0


# ---------------------------------------------------------------------------
# remove_prefix
# ---------------------------------------------------------------------------

def test_remove_prefix_removes_existing_prefix():
    """remove_prefix strips the prefix when it exists."""
    result = aws_tools.remove_prefix('profile myprofile', 'profile ')
    logger.info("remove_prefix('profile myprofile', 'profile ') => %r", result)
    assert result == 'myprofile'


def test_remove_prefix_leaves_text_unchanged_when_no_prefix():
    """remove_prefix returns the text unchanged when the prefix is absent."""
    result = aws_tools.remove_prefix('myprofile', 'profile ')
    logger.info("remove_prefix('myprofile', 'profile ') => %r", result)
    assert result == 'myprofile'


def test_remove_prefix_empty_prefix():
    """remove_prefix with empty prefix returns the original text."""
    result = aws_tools.remove_prefix('hello', '')
    logger.info("remove_prefix('hello', '') => %r", result)
    assert result == 'hello'


# ---------------------------------------------------------------------------
# debug / error / info
# ---------------------------------------------------------------------------

@patch('builtins.print')
def test_debug_prints_when_level_met(mock_print):
    """debug prints when debug_level >= msg_level."""
    aws_tools.debug_level = 2
    aws_tools.debug('test message', 1)
    logger.info("print called with => %s", mock_print.call_args)
    mock_print.assert_called_once_with('DEBUG: test message')
    aws_tools.debug_level = 0


@patch('builtins.print')
def test_debug_does_not_print_when_level_not_met(mock_print):
    """debug does not print when debug_level < msg_level."""
    aws_tools.debug_level = 0
    aws_tools.debug('test message', 2)
    logger.info("print not called (debug_level=0, msg_level=2)")
    mock_print.assert_not_called()


@patch('builtins.print')
def test_error_prints_correct_format(mock_print):
    """error prints with ERROR: prefix."""
    aws_tools.error('something went wrong')
    logger.info("print called with => %s", mock_print.call_args)
    mock_print.assert_called_once_with('ERROR: something went wrong')


@patch('builtins.print')
def test_info_prints_correct_format(mock_print):
    """info prints with INFO: prefix."""
    aws_tools.info('all good')
    logger.info("print called with => %s", mock_print.call_args)
    mock_print.assert_called_once_with('INFO: all good')


# ---------------------------------------------------------------------------
# arg_valid_date
# ---------------------------------------------------------------------------

def test_arg_valid_date_valid_format():
    """arg_valid_date returns YYYYMMDD string for valid input."""
    result = aws_tools.arg_valid_date('2024-JAN-15')
    logger.info("arg_valid_date('2024-JAN-15') => %r", result)
    assert result == '20240115'


def test_arg_valid_date_invalid_format_raises():
    """arg_valid_date raises ArgumentTypeError for invalid format."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_date('2024-01-15')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# arg_valid_key
# ---------------------------------------------------------------------------

def test_arg_valid_key_appends_slash():
    """arg_valid_key appends '/' to a key that lacks it."""
    result = aws_tools.arg_valid_key('my/prefix')
    logger.info("arg_valid_key('my/prefix') => %r", result)
    assert result == 'my/prefix/'


def test_arg_valid_key_keeps_trailing_slash():
    """arg_valid_key does not double-slash a key that already ends with '/'."""
    result = aws_tools.arg_valid_key('my/prefix/')
    logger.info("arg_valid_key('my/prefix/') => %r", result)
    assert result == 'my/prefix/'


def test_arg_valid_key_empty_string():
    """arg_valid_key returns empty string unchanged."""
    result = aws_tools.arg_valid_key('')
    logger.info("arg_valid_key('') => %r", result)
    assert result == ''


def test_arg_valid_key_invalid_character_raises():
    """arg_valid_key raises ArgumentTypeError when the key has a forbidden character."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_key('prefix{}')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


def test_arg_valid_key_no_slash_append():
    """arg_valid_key with append_slash=False does not append slash."""
    result = aws_tools.arg_valid_key('my/prefix', append_slash=False)
    logger.info("arg_valid_key('my/prefix', append_slash=False) => %r", result)
    assert result == 'my/prefix'


# ---------------------------------------------------------------------------
# arg_valid_accountid
# ---------------------------------------------------------------------------

def test_arg_valid_accountid_none_returns_empty_list():
    """arg_valid_accountid returns [] when None is passed."""
    result = aws_tools.arg_valid_accountid(None)
    logger.info("arg_valid_accountid(None) => %r", result)
    assert result == []


def test_arg_valid_accountid_single_valid():
    """arg_valid_accountid returns a list with one account ID."""
    result = aws_tools.arg_valid_accountid('123456789012')
    logger.info("arg_valid_accountid('123456789012') => %r", result)
    assert result == ['123456789012']


def test_arg_valid_accountid_multiple_valid():
    """arg_valid_accountid returns a list with multiple account IDs."""
    result = aws_tools.arg_valid_accountid('123456789012,210987654321')
    logger.info("arg_valid_accountid('123456789012,210987654321') => %r", result)
    assert result == ['123456789012', '210987654321']


def test_arg_valid_accountid_invalid_raises():
    """arg_valid_accountid raises ArgumentTypeError for non-numeric or wrong-length IDs."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_accountid('12345')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# arg_valid_regions
# ---------------------------------------------------------------------------

def test_arg_valid_regions_empty_returns_empty_list():
    """arg_valid_regions returns [] for empty string."""
    result = aws_tools.arg_valid_regions('')
    logger.info("arg_valid_regions('') => %r", result)
    assert result == []


def test_arg_valid_regions_valid_single():
    """arg_valid_regions returns a list with a valid region."""
    result = aws_tools.arg_valid_regions('us-east-1')
    logger.info("arg_valid_regions('us-east-1') => %r", result)
    assert result == ['us-east-1']


def test_arg_valid_regions_valid_multiple_sorted():
    """arg_valid_regions returns sorted deduplicated regions."""
    result = aws_tools.arg_valid_regions('us-west-2,us-east-1,us-east-1')
    logger.info("arg_valid_regions('us-west-2,us-east-1,us-east-1') => %r", result)
    assert result == ['us-east-1', 'us-west-2']


def test_arg_valid_regions_invalid_format_raises():
    """arg_valid_regions raises ArgumentTypeError for invalid region format."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_regions('invalid-region')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# arg_valid_iam_role_duration
# ---------------------------------------------------------------------------

def test_arg_valid_iam_role_duration_none_returns_none():
    """arg_valid_iam_role_duration returns None when None is passed."""
    result = aws_tools.arg_valid_iam_role_duration(None)
    logger.info("arg_valid_iam_role_duration(None) => %r", result)
    assert result is None


def test_arg_valid_iam_role_duration_valid():
    """arg_valid_iam_role_duration returns int for a valid duration."""
    result = aws_tools.arg_valid_iam_role_duration('900')
    logger.info("arg_valid_iam_role_duration('900') => %r", result)
    assert result == 900


def test_arg_valid_iam_role_duration_too_low_raises():
    """arg_valid_iam_role_duration raises for value below 900."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_iam_role_duration('899')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


def test_arg_valid_iam_role_duration_too_high_raises():
    """arg_valid_iam_role_duration raises for value above 3600."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_iam_role_duration('3601')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


def test_arg_valid_iam_role_duration_non_numeric_raises():
    """arg_valid_iam_role_duration raises for non-numeric input."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_iam_role_duration('abc')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# arg_valid_bucket_name
# ---------------------------------------------------------------------------

def test_arg_valid_bucket_name_valid():
    """arg_valid_bucket_name returns the name for a valid bucket."""
    result = aws_tools.arg_valid_bucket_name('my-valid-bucket')
    logger.info("arg_valid_bucket_name('my-valid-bucket') => %r", result)
    assert result == 'my-valid-bucket'


def test_arg_valid_bucket_name_invalid_raises():
    """arg_valid_bucket_name raises for an invalid bucket name."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.arg_valid_bucket_name('INVALID_BUCKET')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# args_valid_iam_role_arn
# ---------------------------------------------------------------------------

def test_args_valid_iam_role_arn_valid():
    """args_valid_iam_role_arn returns the ARN for a valid input."""
    arn = 'arn:aws:iam::123456789012:role/MyRole'
    result = aws_tools.args_valid_iam_role_arn(arn)
    logger.info("args_valid_iam_role_arn('%s') => %r", arn, result)
    assert result == arn


def test_args_valid_iam_role_arn_invalid_raises():
    """args_valid_iam_role_arn raises for an invalid ARN."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.args_valid_iam_role_arn('not-an-arn')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# args_valid_sqs_name
# ---------------------------------------------------------------------------

def test_args_valid_sqs_name_valid():
    """args_valid_sqs_name returns the name for a valid SQS queue name."""
    result = aws_tools.args_valid_sqs_name('my-queue_123')
    logger.info("args_valid_sqs_name('my-queue_123') => %r", result)
    assert result == 'my-queue_123'


def test_args_valid_sqs_name_invalid_raises():
    """args_valid_sqs_name raises for an invalid SQS queue name."""
    with pytest.raises(argparse.ArgumentTypeError) as exc_info:
        aws_tools.args_valid_sqs_name('invalid name!')
    logger.info("raised ArgumentTypeError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# arg_validate_security_lake_auth_params
# ---------------------------------------------------------------------------

@patch('builtins.print')
def test_arg_validate_security_lake_no_iam_role_exits(mock_print):
    """arg_validate_security_lake_auth_params exits when iam_role_arn is None."""
    with pytest.raises(SystemExit) as exc_info:
        aws_tools.arg_validate_security_lake_auth_params(
            external_id='ext', name='queue', iam_role_arn=None, profile='default'
        )
    logger.info("SystemExit code => %s", exc_info.value.code)
    assert exc_info.value.code == 21


@patch('builtins.print')
def test_arg_validate_security_lake_no_queue_exits(mock_print):
    """arg_validate_security_lake_auth_params exits when name is None."""
    with pytest.raises(SystemExit) as exc_info:
        aws_tools.arg_validate_security_lake_auth_params(
            external_id='ext', name=None, iam_role_arn='arn:aws:iam::123:role/r', profile='default'
        )
    logger.info("SystemExit code => %s", exc_info.value.code)
    assert exc_info.value.code == 21


@patch('builtins.print')
def test_arg_validate_security_lake_no_external_id_exits(mock_print):
    """arg_validate_security_lake_auth_params exits when external_id is None."""
    with pytest.raises(SystemExit) as exc_info:
        aws_tools.arg_validate_security_lake_auth_params(
            external_id=None, name='queue', iam_role_arn='arn:aws:iam::123:role/r', profile='default'
        )
    logger.info("SystemExit code => %s", exc_info.value.code)
    assert exc_info.value.code == 21


@patch('builtins.print')
def test_arg_validate_security_lake_all_params_valid_does_not_exit(mock_print):
    """arg_validate_security_lake_auth_params does not exit when all required params are provided."""
    aws_tools.arg_validate_security_lake_auth_params(
        external_id='ext', name='queue', iam_role_arn='arn:aws:iam::123:role/r', profile='default'
    )
    logger.info("No SystemExit raised — all required params provided")


# ---------------------------------------------------------------------------
# get_aws_config_params
# ---------------------------------------------------------------------------

def test_get_aws_config_params_returns_config_parser():
    """get_aws_config_params returns a RawConfigParser instance."""
    import configparser
    result = aws_tools.get_aws_config_params()
    logger.info("get_aws_config_params() type => %s", type(result).__name__)
    assert isinstance(result, configparser.RawConfigParser)
