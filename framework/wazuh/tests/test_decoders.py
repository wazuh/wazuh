# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open
import pytest

from wazuh.decoder import Decoder
from wazuh.exception import WazuhException

decoder_ossec_conf = {
    'decoder_dir': ['ruleset/decoders'],
    'decoder_exclude': 'decoders1.xml'
}

decoder_contents = '''
<decoder name="agent-buffer">
  <parent>wazuh</parent>
  <prematch offset="after_parent">^Agent buffer:</prematch>
  <regex offset="after_prematch">^ '(\S+)'.</regex>
  <order>level</order>
</decoder>
    '''


def decoders_files(file_path):
    """
    Returns a list of decoders names
    :param file_path: A glob file path containing *.xml in the end.
    :return: A generator
    """
    return map(lambda x: file_path.replace('*.xml', f'decoders{x}.xml'), range(2))


@pytest.mark.parametrize('func', [
    Decoder.get_decoders_files,
    Decoder.get_decoders
])
@pytest.mark.parametrize('status', [
    None,
    'all',
    'enabled',
    'disabled',
    'random'
])
@patch('wazuh.decoder.glob', side_effect=decoders_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=decoder_ossec_conf)
def test_get_decoders_file_status(mock_config, mock_glob, status, func):
    """
    Tests getting decoders using status filter
    """
    m = mock_open(read_data=decoder_contents)
    if status == 'random':
        with pytest.raises(WazuhException, match='.* 1202 .*'):
            func(status=status)
    else:
        with patch('builtins.open', m):
            d_files = func(status=status)
            if isinstance(d_files['items'][0], Decoder):
                d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
            if status is None or status == 'all':
                assert d_files['totalItems'] == 2
                assert d_files['items'][0]['status'] == 'enabled'
                assert d_files['items'][1]['status'] == 'disabled'
            else:
                assert d_files['totalItems'] == 1
                assert d_files['items'][0]['status'] == status


@pytest.mark.parametrize('func', [
    Decoder.get_decoders_files,
    Decoder.get_decoders
])
@pytest.mark.parametrize('path', [
    None,
    'ruleset/decoders',
    'random'
])
@patch('wazuh.decoder.glob', side_effect=decoders_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=decoder_ossec_conf)
def test_get_decoders_file_path(mock_config, mock_glob, path, func):
    """
    Tests getting decoders files filtering by path
    """
    m = mock_open(read_data=decoder_contents)
    with patch('builtins.open', m):
        d_files = func(path=path)
        if path == 'random':
            assert d_files['totalItems'] == 0
            assert len(d_files['items']) == 0
        else:
            assert d_files['totalItems'] == 2
            if isinstance(d_files['items'][0], Decoder):
                d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
            assert d_files['items'][0]['path'] == 'ruleset/decoders'


@pytest.mark.parametrize('func', [
    Decoder.get_decoders_files,
    Decoder.get_decoders
])
@pytest.mark.parametrize('offset, limit', [
    (0, 0),
    (0, 1),
    (0, 500),
    (1, 500),
    (2, 500),
    (3, 500)
])
@patch('wazuh.decoder.glob', side_effect=decoders_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=decoder_ossec_conf)
def test_get_decoders_file_pagination(mock_config, mock_glob, offset, limit, func):
    """
    Tests getting decoders files using offset and limit
    """
    if limit > 0:
        m = mock_open(read_data=decoder_contents)
        with patch('builtins.open', m):
            d_files = func(offset=offset, limit=limit)
            limit = d_files['totalItems'] if limit > d_files['totalItems'] else limit
            assert d_files['totalItems'] == 2
            assert len(d_files['items']) == (limit - offset if limit > offset else 0)
    else:
        with pytest.raises(WazuhException, match='.* 1406 .*'):
            Decoder.get_decoders_files(offset=offset, limit=limit)


@pytest.mark.parametrize('func', [
    Decoder.get_decoders_files,
    Decoder.get_decoders
])
@pytest.mark.parametrize('sort', [
    None,
    {"fields": ["file"], "order": "asc"},
    {"fields": ["file"], "order": "desc"}
])
@patch('wazuh.decoder.glob', side_effect=decoders_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=decoder_ossec_conf)
def test_get_decoders_file_sort(mock_config, mock_glob, sort, func):
    """
    Tests getting decoders files and sorting results
    """
    m = mock_open(read_data=decoder_contents)
    with patch('builtins.open', m):
        d_files = func(sort=sort)
        if isinstance(d_files['items'][0], Decoder):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if sort is not None:
            assert d_files['items'][0]['file'] == f"decoders{'0' if sort['order'] == 'asc' else '1'}.xml"


@pytest.mark.parametrize('func', [
    Decoder.get_decoders_files,
    Decoder.get_decoders
])
@pytest.mark.parametrize('search', [
    None,
    {"value": "1", "negation": 0},
    {"value": "1", "negation": 1}
])
@patch('wazuh.decoder.glob', side_effect=decoders_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=decoder_ossec_conf)
def test_get_decoders_file_search(mock_config, mock_glob, search, func):
    """
    Tests getting decoders files and searching results
    """
    m = mock_open(read_data=decoder_contents)
    with patch('builtins.open', m):
        d_files = Decoder.get_decoders_files(search=search)
        if isinstance(d_files['items'][0], Decoder):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if search is not None:
            assert d_files['items'][0]['file'] == f"decoders{'0' if search['negation'] else '1'}.xml"
