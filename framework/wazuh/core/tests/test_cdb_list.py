#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import mock_open, patch

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core import common
        from wazuh.core.cdb_list import check_path, get_list_from_file, get_relative_path, iterate_lists, \
            split_key_value_with_quotes
        from wazuh.core.exception import WazuhError


# Variables

BAD_CDB_FORMAT_ERROR_CODE = 1800
LIST_FILE_NOT_FOUND_ERROR_CODE = 1802
PERMISSION_ERROR_CODE = 1803
INVALID_FILEPATH_ERROR_CODE = 1804

ABSOLUTE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "test_cdb_list")
RELATIVE_PATH = os.path.join("framework", "wazuh", "core", "tests", "data", "test_cdb_list")
PATH_FILE = os.path.join(RELATIVE_PATH, "test_lists")

CONTENT_FILE = [{'key': 'test-wazuh-w', 'value': 'write'},
                {'key': 'test-wazuh-r', 'value': 'read'},
                {'key': 'test-wazuh-a', 'value': 'attribute'},
                {'key': 'test-wazuh-x', 'value': 'execute'},
                {'key': 'test-wazuh-c', 'value': 'command'},
                {'key': 'test-key', 'value': 'value:1'},
                {'key': 'test-key:1', 'value': 'value'},
                {'key': 'test-key:2', 'value': 'value:2'},
                {'key': 'test-key::::::3', 'value': 'value3'},
                {'key': 'test-key4', 'value': 'value:::4'}]


# Tests

@pytest.mark.parametrize("relative_path", ["testpath", "complex test path/with/sub/dir"])
def test_get_relative_path(relative_path):
    """Test `get_relative_path` core functionality.

    This will create a full path from the relative path provided and then pass it to `get_relative_path`. The result
    must be the same as the original `relative_path` provided.

    Parameters
    ----------
    relative_path : str
        Relative path to create a full path and pass it to `get_relative_path`.
    """
    full_path = os.path.join(common.ossec_path, relative_path)
    assert relative_path == get_relative_path(full_path)


@pytest.mark.parametrize('path, error_expected', [
    ("etc/lists/valid", False),
    ("etc/lists/valid/with/subdirs", False),
    ("etc/", True),
    ("etc/lists", True),
    ("/etc/lists", True),
    ("etc/invalid/lists", True),
    ("./", True),
    ("../", True),
    ("etc/lists/../", True),
    ("etc/lists/../invalid", True)
])
def test_check_path(path, error_expected):
    """Test `check_path core` functionality.

    `Check_path` must ensure that the provided paths are well formated or not.

    Parameters
    ----------
    path : str
        A relative path with a valid or invalid format.
    error_expected : int
        Expected error to be raised by check_path due to an invalid path format.
    """
    try:
        check_path(path)
        assert not error_expected
    except WazuhError as error:
        if error._code != 1801 or not error_expected:
            raise


@pytest.mark.parametrize('only_names', [True, False])
@pytest.mark.parametrize('path', [ABSOLUTE_PATH, os.path.join(ABSOLUTE_PATH, "subdir")])
def test_iterate_lists(only_names, path):
    """Test `iterate_lists` core functionality.

    `Iterate_list` must get the content of all CDB lists in a specified path skipping `.cdb` and `.swp` files. It will
    return a list of dictionaries.

    Parameters
    ----------
    only_names : bool
        If this parameter is true, only the name of all lists will be showed by `iterate_lists` instead of its content.
    path : str
        Path to iterate lists from.
    """
    required_fields = ['relative_dirname', 'filename'] if only_names else ['relative_dirname', 'filename', 'items']

    common.reset_context_cache()
    result = iterate_lists(absolute_path=path, only_names=only_names)
    assert isinstance(result, list)
    assert len(result) != 0
    for entry in result:
        for field in required_fields:
            assert field in entry


@pytest.mark.parametrize('line, expected_key, expected_value', [
    ('"example:0":value0', 'example:0', 'value0'),
    ('"example:1":value:1', 'example:1', 'value:1'),
    ('"example:2":"value:2"', 'example:2', 'value:2'),
    ('example3:"value:3"', 'example3', 'value:3'),
    ('"example:4":a"value:4"', None, None),
    ('"example:5":"value:5"a', None, None),
    ('a"example:6":"value:6"', None, None),
    ('a"example:7":value7', None, None),
    ('"example:8"a:value8', None, None),
    ('example9:a"value:9"', None, None),
    ('example10:"value:10"a', None, None)
])
def test_split_key_value_with_quotes(line, expected_key, expected_value):
    """Test `split_key_value_with_quotes` functionality.

    Parameters
    ----------
    line : str
        Line to be split.
    expected_key : str
        Expected key of the CDB list line.
    expected_value : str
        Expected value of the CDB list line.
    """
    if expected_key and expected_value:
        key, value = split_key_value_with_quotes(line)
        assert key == expected_key and value == expected_value
    else:
        with pytest.raises(WazuhError) as e:
            split_key_value_with_quotes(line)
        assert e.value.code == 1800


def test_get_list_from_file():
    """Test basic `get_list_from_file` core functionality.

    `get_list_from_file` must retrieve the content of a CDB file.
    """
    assert get_list_from_file(PATH_FILE) == CONTENT_FILE


@pytest.mark.parametrize("error_to_raise, wazuh_error_code", [
    (OSError(2, "No such file or directory"), LIST_FILE_NOT_FOUND_ERROR_CODE),
    (OSError(13, "Permission denied"), PERMISSION_ERROR_CODE),
    (OSError(21, "Is a directory"), INVALID_FILEPATH_ERROR_CODE),
    (OSError(1, "Random"), None),
    (ValueError(), BAD_CDB_FORMAT_ERROR_CODE)
])
def test_get_list_from_file_with_errors(error_to_raise, wazuh_error_code):
    """Test `get_list_from_file` core functionality when using invalid files or paths as parameter.

    `get_list_from_file` must raise the proper WazuhError when facing certain scenarios like a Permission Denied error
    when opening a file.

    Parameters
    ----------
    error_to_raise : OSError
        The `OSError` that `get_list_from_file` must catch when trying to open a file.
    wazuh_error_code : int
        Error code of the `WazuhError` that must be raised by `get_list_from_file` when the specified `OSError` occurrs.
    """
    with patch("builtins.open", mock_open()) as mock:
        mock.side_effect = error_to_raise
        try:
            get_list_from_file("some_path")
            pytest.fail("No exception was raised hence failing the test")
        except WazuhError as e:
            assert e.code == wazuh_error_code
        except Exception as e:
            assert e.args == (1, "Random")
