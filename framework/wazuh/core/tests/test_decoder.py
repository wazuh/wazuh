#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import stat
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhException
        from wazuh.core import decoder


# Variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Tests

@pytest.mark.parametrize("detail, value, details, expected_result", [
    ("parent", "wazuh", {'regex': ['regex00']}, {'parent': 'wazuh', 'regex': ['regex00']}),
    ("prematch", "^Agent buffer:", {}, {'prematch': "^Agent buffer:"}),
    ("regex", "regex01", {}, {'regex': ['regex01']}),
    ("regex", "regex02", {'regex': ['regex03']}, {'regex': ['regex03', 'regex02']}),
    ("order", "level", {}, {'order': 'level'})
])
def test_add_detail(detail, value, details, expected_result):
    # UUT call
    decoder.add_detail(detail, value, details)
    assert details == expected_result


@pytest.mark.parametrize("status, expected_result", [
    (None, "all"),
    ("all", "all"),
    ("enabled", "enabled"),
    ("disabled", "disabled"),
    ("wrong", WazuhError(1202))
])
def test_check_status(status, expected_result):
    try:
        # UUT call
        result = decoder.check_status(status)
        assert result == expected_result
    except WazuhError as e:
        # If the UUT call returns an exception we check it has the appropriate error code
        assert e.code == expected_result.code


@pytest.mark.parametrize("filename, relative_dirname, status, permissions, exception", [
    ('test1_decoders.xml', 'decoders', "all", 777, None),
    ('test2_decoders.xml', 'decoders', "enabled", 777, None),
    ('wrong_decoders.xml', 'decoders', "all", 777, WazuhInternalError(1501)),
    ('non_existing.xml', 'decoders', "disabled", 777, WazuhError(1502)),
    ('test1_decoders.xml', 'decoders', "all", 000, WazuhError(1502)),
])
@patch('wazuh.core.common.ossec_path', new=test_data_path)
def test_load_decoders_from_file(filename, relative_dirname, status, permissions, exception):
    full_file_path = os.path.join(test_data_path, relative_dirname, filename)
    try:
        old_permissions = stat.S_IMODE(os.lstat(full_file_path).st_mode)
    except FileNotFoundError:
        old_permissions = None
    try:
        # Set file permissions if the file exists
        os.path.exists(full_file_path) and os.chmod(full_file_path, permissions)
        # UUT call
        result = decoder.load_decoders_from_file(filename, relative_dirname, status)
        # Assert result is a list with at least one dict element with the appropriate fields
        assert isinstance(result, list)
        assert len(result) != 0
        for item in result:
            assert (item['filename'], item['relative_dirname'], item['status']) == (filename, relative_dirname, status)
            assert {'name', 'position', 'details'}.issubset(set(item))
    except WazuhException as e:
        # If the UUT call returns an exception we check it has the appropriate error code
        assert e.code == exception.code
    finally:
        # Set file permissions back to 777 after test if the file exists
        os.path.exists(full_file_path) and os.chmod(full_file_path, old_permissions)


@patch('wazuh.core.common.ossec_path', new=test_data_path)
def test_load_decoders_from_file_details():
    decoder_file = 'test3_decoders.xml'
    decoder_path = 'decoders'
    details_result = {
        'program_name': {
            'pattern': 'test_program_name',
            'type': 'osregex'
        },
        'prematch': {
            'pattern': 'test_prematch'
        },
        'regex': {
            'pattern': 'test_regex',
            'type': 'pcre2'
        },
        'order': 'test_order'
    }
    result = decoder.load_decoders_from_file(decoder_file, decoder_path, 'enabled')
    assert result[0]['details'] == details_result
