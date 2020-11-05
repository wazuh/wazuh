#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import stat
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.getgrnam'):
    with patch('wazuh.core.common.getpwnam'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.core.exception import WazuhInternalError, WazuhError
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh import decoder


# Variables

test_data_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
decoder_ossec_conf = {
    'ruleset': {
        'decoder_dir': ['core/tests/data/decoders'],
        'decoder_exclude': 'test2_decoders.xml'
    }
}

decoder_ossec_conf_2 = {
    'ruleset': {
        'decoder_dir': ['core/tests/data/decoders'],
        'decoder_exclude': 'wrong_decoders.xml'
    }
}


# Module patches

@pytest.fixture(scope='module', autouse=True)
def mock_ossec_path():
    with patch('wazuh.core.common.ossec_path', new=test_data_path):
        with patch('wazuh.core.configuration.get_ossec_conf', return_value=decoder_ossec_conf):
            yield


# Tests

@pytest.mark.parametrize('names, status, filename, relative_dirname, parents, expected_names, expected_total_failed', [
    (None, None, None, None, False, {'agent-buffer', 'json', 'agent-upgrade', 'wazuh', 'agent-restart'}, 0),
    (['agent-buffer'], None, None, None, False, {'agent-buffer'}, 0),
    (['agent-buffer', 'non_existing'], None, None, None, False, {'agent-buffer'}, 1),
    (None, 'enabled', None, None, False, {'agent-buffer', 'agent-upgrade', 'wazuh', 'agent-restart'}, 0),
    (None, 'disabled', None, None, False, {'json'}, 0),
    (['agent-upgrade', 'non_existing', 'json'], 'enabled', None, None, False, {'agent-upgrade'}, 1),
    (None, None, 'test1_decoders.xml', None, False, {'agent-buffer', 'agent-upgrade', 'wazuh', 'agent-restart'}, 0),
    (None, None, 'test2_decoders.xml', 'core/tests/data/decoders', False, {'json'}, 0),
    (None, 'all', None, 'core/tests/data/decoders', True, {'wazuh', 'json'}, 0),
    (None, 'all', None, 'nothing_here', False, set(), 0)
])
def test_get_decoders(names, status, filename, relative_dirname, parents, expected_names, expected_total_failed):
    wrong_decoder_original_path = os.path.join(test_data_path, 'core/tests/data/decoders', 'wrong_decoders.xml')
    wrong_decoder_tmp_path = os.path.join(test_data_path, 'core/tests/data', 'wrong_decoders.xml')
    try:
        os.rename(wrong_decoder_original_path, wrong_decoder_tmp_path)
        # UUT call
        result = decoder.get_decoders(names=names, status=status, filename=filename, relative_dirname=relative_dirname,
                                      parents=parents)
        assert isinstance(result, AffectedItemsWazuhResult)
        # Build result names set from response for filter validation
        result_names = {d['name'] for d in result.affected_items}
        assert result_names == expected_names
        # Assert failed items length matches expected result
        assert result.total_failed_items == expected_total_failed
    finally:
        os.rename(wrong_decoder_tmp_path, wrong_decoder_original_path)


@pytest.mark.parametrize('conf, exception', [
    (decoder_ossec_conf, None),
    ({'ruleset': None}, WazuhInternalError(1500))
])
def test_get_decoders_files(conf, exception):
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=conf):
        try:
            # UUT call
            result = decoder.get_decoders_files()
            assert isinstance(result, AffectedItemsWazuhResult)
            # Assert result is a list with at least one dict element with the appropriate fields
            assert isinstance(result.affected_items, list)
            assert len(result.affected_items) != 0
            for item in result.affected_items:
                assert {'filename', 'relative_dirname', 'status'}.issubset(set(item))
            assert result.total_affected_items == len(result.affected_items)
        except WazuhInternalError as e:
            # If the UUT call returns an exception we check it has the appropriate error code
            assert e.code == exception.code


@pytest.mark.parametrize('status, relative_dirname, filename, expected_files', [
    (None, None, None, {'test1_decoders.xml', 'test2_decoders.xml', 'wrong_decoders.xml'}),
    ('all', None, None, {'test1_decoders.xml', 'test2_decoders.xml', 'wrong_decoders.xml'}),
    ('enabled', None, None, {'test1_decoders.xml', 'wrong_decoders.xml'}),
    ('disabled', None, None, {'test2_decoders.xml'}),
    ('all', 'core/tests/data/decoders', None, {'test1_decoders.xml', 'test2_decoders.xml', 'wrong_decoders.xml'}),
    ('all', 'wrong_path', None, set()),
    ('disabled', 'core/tests/data/decoders', None, {'test2_decoders.xml'}),
    (None, 'core/tests/data/decoders', 'test2_decoders.xml', {'test2_decoders.xml'}),
    ('disabled', 'core/tests/data/decoders', 'test2_decoders.xml', {'test2_decoders.xml'}),
    ('enabled', 'core/tests/data/decoders', 'test2_decoders.xml', set()),
    ('enabled', None, 'test1_decoders.xml', {'test1_decoders.xml'}),
    (None, None, ['test1_decoders.xml', 'test2_decoders.xml'], {'test1_decoders.xml', 'test2_decoders.xml'}),
    ('enabled', None, ['test1_decoders.xml', 'test2_decoders.xml'], {'test1_decoders.xml'}),
    ('disabled', None, ['wrong_decoders.xml', 'test2_decoders.xml', 'non_existing.xml'], {'test2_decoders.xml'}),
    (None, None, 'non_existing.xml', set()),
])
def test_get_decoders_files_filters(status, relative_dirname, filename, expected_files):
    # UUT call
    result = decoder.get_decoders_files(status=status, relative_dirname=relative_dirname, filename=filename)
    assert isinstance(result, AffectedItemsWazuhResult)
    # Build result_files set from response for filter validation
    result_files = {d['filename'] for d in result.affected_items}
    assert result_files == expected_files


@pytest.mark.parametrize('filename', [
    'test1_decoders.xml',
    'test2_decoders.xml',
    'wrong_decoders.xml',
])
def test_get_file(filename):
    # UUT call
    result = decoder.get_file(filename=filename)
    # We assert the result is a plain text str
    assert isinstance(result, str)


def test_get_file_exceptions():
    with pytest.raises(WazuhError, match=r'.* 1503 .*'):
        # UUT 1st call using a non-existing file that returns 0 decoders
        decoder.get_file(filename='non_existing_file.xml')
    with patch('builtins.open', return_value=Exception):
        with pytest.raises(WazuhInternalError, match=r'.* 1501 .*'):
            # UUT 2nd call forcing en error opening decoder file
            decoder.get_file(filename='test1_decoders.xml')
    with pytest.raises(WazuhError, match=r'.* 1502 .*'):
        filename = 'test2_decoders.xml'
        old_permissions = stat.S_IMODE(os.lstat(os.path.join(
            test_data_path, 'core/tests/data/decoders', filename)).st_mode)
        try:
            os.chmod(os.path.join(test_data_path, 'core/tests/data/decoders', filename), 000)
            # UUT 3rd call forcing a permissions error opening decoder file
            decoder.get_file(filename=filename)
        finally:
            os.chmod(os.path.join(test_data_path, 'core/tests/data/decoders', filename), old_permissions)
