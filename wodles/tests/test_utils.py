# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_utils.py -v --log-cli-level=DEBUG

import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

logger = logging.getLogger(__name__)

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import utils


@pytest.fixture(autouse=True)
def clear_lru_caches():
    """Clear all lru_cache caches before each test to avoid state leakage."""
    utils.find_wazuh_path.cache_clear()
    utils.get_wazuh_version.cache_clear()
    utils.get_wazuh_revision.cache_clear()
    utils.get_wazuh_type.cache_clear()
    yield
    utils.find_wazuh_path.cache_clear()
    utils.get_wazuh_version.cache_clear()
    utils.get_wazuh_revision.cache_clear()
    utils.get_wazuh_type.cache_clear()


# ---------------------------------------------------------------------------
# find_wazuh_path
# ---------------------------------------------------------------------------

def test_find_wazuh_path_returns_string():
    """find_wazuh_path always returns a string."""
    result = utils.find_wazuh_path()
    logger.info("find_wazuh_path() type=%s value=%r", type(result).__name__, result)
    assert isinstance(result, str)


def test_find_wazuh_path_returns_parent_of_wodles():
    """find_wazuh_path returns the parent directory of the 'wodles' segment, not wodles itself."""
    path = utils.find_wazuh_path()
    logger.info("find_wazuh_path() => %r", path)
    assert not path.endswith('wodles')


def test_find_wazuh_path_no_wodles_in_path():
    """find_wazuh_path returns '' when __file__ is not under a 'wodles' directory."""
    with patch('utils.os.path.abspath', return_value='/tmp/some/other/dir'):
        with patch('utils.os.path.dirname', return_value='/tmp/some/other/dir'):
            utils.find_wazuh_path.cache_clear()
            result = utils.find_wazuh_path()
    logger.info("find_wazuh_path() with no 'wodles' segment => %r", result)
    assert result == ''


def test_find_wazuh_path_cache():
    """find_wazuh_path is only computed once due to lru_cache."""
    with patch('utils.os.path.abspath', return_value='/opt/wazuh/wodles') as mock_abspath:
        utils.find_wazuh_path.cache_clear()
        utils.find_wazuh_path()
        utils.find_wazuh_path()
        logger.info("os.path.abspath call_count after 2 find_wazuh_path() calls => %d", mock_abspath.call_count)
        assert mock_abspath.call_count == 1


def test_find_wazuh_path_relative_path_sentinel():
    """find_wazuh_path handles a single-component relative path (sentinel for relative paths branch)."""
    # os.path.split('wodles') => ('', 'wodles'), so parts[1] == abs_path triggers the elif branch.
    with patch('utils.os.path.abspath', return_value='wodles'):
        utils.find_wazuh_path.cache_clear()
        result = utils.find_wazuh_path()
    # 'wodles' is found at index 0, so range(0, 0) produces no iterations → wazuh_path == ''
    assert result == ''


# ---------------------------------------------------------------------------
# call_wazuh_control
# ---------------------------------------------------------------------------

@patch('utils.find_wazuh_path', return_value='/var/ossec')
@patch('utils.subprocess.Popen')
def test_call_wazuh_control_returns_stdout(mock_popen, mock_path):
    """call_wazuh_control returns the decoded stdout of the subprocess."""
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = (b'WAZUH_VERSION="5.0.0"\n', None)
    mock_popen.return_value = mock_proc

    result = utils.call_wazuh_control('info')
    logger.info("call_wazuh_control('info') => %r", result)
    logger.info("Popen called with => %s", mock_popen.call_args)

    assert result == 'WAZUH_VERSION="5.0.0"\n'
    mock_popen.assert_called_once_with(
        ['/var/ossec/bin/wazuh-control', 'info'],
        stdout=utils.subprocess.PIPE,
    )


@patch('utils.find_wazuh_path', return_value='/var/ossec')
@patch('utils.subprocess.Popen', side_effect=OSError)
@patch('builtins.print')
def test_call_wazuh_control_oserror_exits(mock_print, mock_popen, mock_path):
    """call_wazuh_control prints an error and exits when OSError is raised."""
    with pytest.raises(SystemExit):
        utils.call_wazuh_control('info')
    logger.info("print called with => %s", mock_print.call_args)
    mock_print.assert_called_once_with(
        'ERROR: a problem occurred while executing /var/ossec/bin/wazuh-control'
    )


@patch('utils.find_wazuh_path', return_value='/var/ossec')
@patch('utils.subprocess.Popen', side_effect=ChildProcessError)
@patch('builtins.print')
def test_call_wazuh_control_childprocesserror_exits(mock_print, mock_popen, mock_path):
    """call_wazuh_control prints an error and exits when ChildProcessError is raised."""
    with pytest.raises(SystemExit):
        utils.call_wazuh_control('info')
    logger.info("print called with => %s", mock_print.call_args)
    mock_print.assert_called_once()


# ---------------------------------------------------------------------------
# get_wazuh_info
# ---------------------------------------------------------------------------

@patch('utils.call_wazuh_control', return_value='')
def test_get_wazuh_info_empty_output_returns_error(mock_ctrl):
    """get_wazuh_info returns 'ERROR' when wazuh-control produces no output."""
    result = utils.get_wazuh_info('WAZUH_VERSION')
    logger.info("get_wazuh_info('WAZUH_VERSION') with empty output => %r", result)
    assert result == 'ERROR'


@patch('utils.call_wazuh_control', return_value='WAZUH_VERSION="5.0.0"\nWAZUH_REVISION="1"\n')
def test_get_wazuh_info_no_field_returns_full_output(mock_ctrl):
    """get_wazuh_info returns the full output when field is empty."""
    result = utils.get_wazuh_info('')
    logger.info("get_wazuh_info('') => %r", result)
    assert 'WAZUH_VERSION' in result
    assert 'WAZUH_REVISION' in result


@patch('utils.call_wazuh_control', return_value='WAZUH_VERSION="5.0.0"\nWAZUH_REVISION="1"\nWAZUH_TYPE="server"\n')
def test_get_wazuh_info_version_field(mock_ctrl):
    """get_wazuh_info correctly parses and returns WAZUH_VERSION."""
    result = utils.get_wazuh_info('WAZUH_VERSION')
    logger.info("get_wazuh_info('WAZUH_VERSION') => %r", result)
    assert result == '5.0.0'


@patch('utils.call_wazuh_control', return_value='WAZUH_VERSION="5.0.0"\nWAZUH_REVISION="1"\nWAZUH_TYPE="server"\n')
def test_get_wazuh_info_revision_field(mock_ctrl):
    """get_wazuh_info correctly parses and returns WAZUH_REVISION."""
    result = utils.get_wazuh_info('WAZUH_REVISION')
    logger.info("get_wazuh_info('WAZUH_REVISION') => %r", result)
    assert result == '1'


@patch('utils.call_wazuh_control', return_value='WAZUH_VERSION="5.0.0"\nWAZUH_REVISION="1"\nWAZUH_TYPE="server"\n')
def test_get_wazuh_info_type_field(mock_ctrl):
    """get_wazuh_info correctly parses and returns WAZUH_TYPE."""
    result = utils.get_wazuh_info('WAZUH_TYPE')
    logger.info("get_wazuh_info('WAZUH_TYPE') => %r", result)
    assert result == 'server'


@patch('utils.call_wazuh_control', return_value='WAZUH_VERSION="5.0.0"\nWAZUH_REVISION="1"\nWAZUH_TYPE="server"\n')
def test_get_wazuh_info_unknown_field_raises_keyerror(mock_ctrl):
    """get_wazuh_info raises KeyError for an unknown field."""
    with pytest.raises(KeyError) as exc_info:
        utils.get_wazuh_info('UNKNOWN_FIELD')
    logger.info("get_wazuh_info('UNKNOWN_FIELD') raised KeyError => %s", exc_info.value)


# ---------------------------------------------------------------------------
# get_wazuh_version / get_wazuh_revision / get_wazuh_type
# ---------------------------------------------------------------------------

@patch('utils.get_wazuh_info', return_value='5.0.0')
def test_get_wazuh_version_calls_correct_field(mock_info):
    """get_wazuh_version delegates to get_wazuh_info with 'WAZUH_VERSION'."""
    result = utils.get_wazuh_version()
    logger.info("get_wazuh_version() => %r, get_wazuh_info called with => %s", result, mock_info.call_args)
    assert result == '5.0.0'
    mock_info.assert_called_once_with('WAZUH_VERSION')


@patch('utils.get_wazuh_info', return_value='1')
def test_get_wazuh_revision_calls_correct_field(mock_info):
    """get_wazuh_revision delegates to get_wazuh_info with 'WAZUH_REVISION'."""
    result = utils.get_wazuh_revision()
    logger.info("get_wazuh_revision() => %r, get_wazuh_info called with => %s", result, mock_info.call_args)
    assert result == '1'
    mock_info.assert_called_once_with('WAZUH_REVISION')


@patch('utils.get_wazuh_info', return_value='server')
def test_get_wazuh_type_calls_correct_field(mock_info):
    """get_wazuh_type delegates to get_wazuh_info with 'WAZUH_TYPE'."""
    result = utils.get_wazuh_type()
    logger.info("get_wazuh_type() => %r, get_wazuh_info called with => %s", result, mock_info.call_args)
    assert result == 'server'
    mock_info.assert_called_once_with('WAZUH_TYPE')


@patch('utils.get_wazuh_info', return_value='5.0.0')
def test_get_wazuh_version_cache(mock_info):
    """get_wazuh_version only calls get_wazuh_info once due to lru_cache."""
    utils.get_wazuh_version.cache_clear()
    utils.get_wazuh_version()
    utils.get_wazuh_version()
    logger.info("get_wazuh_info call_count after 2 get_wazuh_version() calls => %d", mock_info.call_count)
    assert mock_info.call_count == 1


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

def test_max_event_size_value():
    """MAX_EVENT_SIZE must equal 65535."""
    logger.info("MAX_EVENT_SIZE => %d", utils.MAX_EVENT_SIZE)
    assert utils.MAX_EVENT_SIZE == 65535


def test_analysisd_path_suffix():
    """ANALYSISD must end with 'queue/sockets/queue'."""
    logger.info("ANALYSISD => %r", utils.ANALYSISD)
    assert utils.ANALYSISD.endswith(os.path.join('queue', 'sockets', 'queue'))
