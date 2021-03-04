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

        from wazuh.core.exception import WazuhInternalError
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh import decoder


# Variables

test_data_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
decoder_ossec_conf = {
    'ruleset': {
        'decoder_dir': ['tests/data/decoders'],
        'decoder_exclude': 'test2_decoders.xml'
    }
}

decoder_ossec_conf_2 = {
    'ruleset': {
        'decoder_dir': ['tests/data/decoders'],
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
    (None, None, 'test2_decoders.xml', 'tests/data/decoders', False, {'json'}, 0),
    (None, 'all', None, 'tests/data/decoders', True, {'wazuh', 'json'}, 0),
    (None, 'all', None, 'nothing_here', False, set(), 0)
])
def test_get_decoders(names, status, filename, relative_dirname, parents, expected_names, expected_total_failed):
    wrong_decoder_original_path = os.path.join(test_data_path, 'tests/data/decoders', 'wrong_decoders.xml')
    wrong_decoder_tmp_path = os.path.join(test_data_path, 'tests/data', 'wrong_decoders.xml')
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
    ('all', 'tests/data/decoders', None, {'test1_decoders.xml', 'test2_decoders.xml', 'wrong_decoders.xml'}),
    ('all', 'wrong_path', None, set()),
    ('disabled', 'tests/data/decoders', None, {'test2_decoders.xml'}),
    (None, 'tests/data/decoders', 'test2_decoders.xml', {'test2_decoders.xml'}),
    ('disabled', 'tests/data/decoders', 'test2_decoders.xml', {'test2_decoders.xml'}),
    ('enabled', 'tests/data/decoders', 'test2_decoders.xml', set()),
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
    'test2_decoders.xml'
])
def test_get_decoder_file(filename):
    """Test get file function.

    Parameters
    ----------
    filename : str
        Decoder filename
    """
    result = decoder.get_decoder_file(filename=filename)
    # Assert the result is an AffectedItemsWazuhResult
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items
    assert not result.failed_items

    result = decoder.get_decoder_file(filename=filename, raw=True)
    # Assert the result is a plain text str
    assert isinstance(result, str)


def test_get_decoder_file_exceptions():
    """Test exceptions on get method."""
    # File does not exist
    result = decoder.get_decoder_file(filename='non_existing_file.xml')
    assert not result.affected_items
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1503

    # Invalid XML
    result = decoder.get_decoder_file(filename='wrong_decoders.xml')
    assert not result.affected_items
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1501

    # File permissions
    filename = 'test2_decoders.xml'
    old_permissions = stat.S_IMODE(os.lstat(os.path.join(
        test_data_path, 'tests/data/decoders', filename)).st_mode)
    try:
        os.chmod(os.path.join(test_data_path, 'tests/data/decoders', filename), 000)
        # UUT 3rd call forcing a permissions error opening decoder file
        result = decoder.get_decoder_file(filename=filename)
        assert not result.affected_items
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1502
    finally:
        os.chmod(os.path.join(test_data_path, 'tests/data/decoders', filename), old_permissions)


@pytest.mark.parametrize('file, overwrite', [
    ('test.xml', False),
    ('test_rules.xml', True),
])
@patch('wazuh.decoder.delete_decoder_file')
@patch('wazuh.decoder.upload_file')
@patch('wazuh.core.utils.copyfile')
@patch('wazuh.decoder.remove')
@patch('wazuh.decoder.safe_move')
@patch('wazuh.core.utils.check_remote_commands')
def test_upload_file(mock_remote_commands, mock_safe_move, mock_remove, mock_copyfile, mock_xml, mock_delete, file, overwrite):
    """Test uploading a decoder file.

    Parameters
    ----------
    file : str
        Decoder filename.
    overwrite : boolean
        True for updating existing files, False otherwise.
    """
    with patch('wazuh.decoder.exists', return_value=overwrite):
        result = decoder.upload_decoder_file(filename=file, content='test', overwrite=overwrite)

        # Assert data match what was expected, type of the result and correct parameters in delete() method.
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        decoder_path = os.path.join('etc', 'decoders', file)
        assert result.affected_items[0] == decoder_path, 'Expected item not found'
        mock_xml.assert_called_once_with('test', decoder_path)
        if overwrite:
            mock_delete.assert_called_once_with(filename=file), 'delete_decoder_file method not called with expected ' \
                                                                'parameter'
            mock_remove.assert_called_once()
            mock_safe_move.assert_called_once()


@patch('wazuh.decoder.delete_decoder_file')
@patch('wazuh.decoder.upload_file')
@patch('wazuh.decoder.safe_move')
@patch('wazuh.core.utils.check_remote_commands')
def test_upload_file_ko(mock_remote_commands, mock_safe_move, mock_xml, mock_delete):
    """Test exceptions on upload function."""
    # Error when file exists and overwrite is not True
    with patch('wazuh.decoder.exists'):
        result = decoder.upload_decoder_file(filename='test_decoders.xml', content='test', overwrite=False)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1905, 'Error code not expected.'

    # Error when content is empty
    result = decoder.upload_decoder_file(filename='no_exist.xml', content='', overwrite=False)
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1112, 'Error code not expected.'

    # Error doing backup
    with patch('wazuh.decoder.exists'):
        result = decoder.upload_decoder_file(filename='test_decoders.xml', content='test', overwrite=True)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1019, 'Error code not expected.'


def test_delete_decoder_file():
    """Test deleting a decoder file."""
    with patch('wazuh.decoder.exists', return_value=True):
        # Assert returned type is AffectedItemsWazuhResult when everything is correct
        with patch('wazuh.decoder.remove'):
            assert(isinstance(decoder.delete_decoder_file(filename='file'), AffectedItemsWazuhResult))


def test_delete_decoder_file_ko():
    """Test exceptions on delete method."""
    # Assert error code when remove() method returns IOError
    with patch('wazuh.decoder.exists', return_value=True):
        with patch('wazuh.manager.remove', side_effect=IOError()):
            result = decoder.delete_decoder_file(filename='file')
            assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
            assert result.render()['data']['failed_items'][0]['error']['code'] == 1907, 'Error code not expected.'

    # Assert error code when decoder does not exist
    result = decoder.delete_decoder_file(filename='file')
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1906, 'Error code not expected.'
