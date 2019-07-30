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
<decoder name="agent-buffer" random="random">
  <parent>wazuh</parent>
  <prematch offset="after_parent">^Agent buffer:</prematch>
  <regex offset="after_prematch">^ '(\S+)'.</regex>
  <order>level</order>
</decoder>
    '''

mocked_items = {
    'items': [{'path': 'mocked_path'}]
}

mock_search = {
    'value': 'a',
    'negation': ''
}

@pytest.fixture()
def open_mock(monkeypatch):
    monkeypatch.setattr("wazuh.decoder.glob", decoders_files)
    monkeypatch.setattr("wazuh.configuration.get_ossec_conf", lambda section: decoder_ossec_conf)
    return mock_open(read_data=decoder_contents)


def decoders_files(file_path):
    """
    Returns a list of decoders names
    :param file_path: A glob file path containing *.xml in the end.
    :return: A generator
    """
    return map(lambda x: file_path.replace('*.xml', f'decoders{x}.xml'), range(2))


def test_decoder__init__():
    dec = Decoder()
    assert dec.file is None
    assert dec.path is None
    assert dec.name is None
    assert dec.position is None
    assert dec.status is None
    assert isinstance(dec.details, dict)


def test_decoder__str__():
    result = Decoder().__str__()
    assert isinstance(result, str)


def test_decoder_to_dict():
    result = Decoder().to_dict()
    assert isinstance(result, dict)


@pytest.mark.parametrize('detail, value, details', [
    ('regex', 'w+', {}),
    ('regex', 'w+', {'regex':'*'}),
    ('random', 'random', {})
])
def test_add_detail(detail, value, details):
    dec = Decoder()
    dec.details = dict(frozenset(details.items()))
    dec.add_detail(detail, value)
    if not details:
        assert isinstance(dec.details[detail], str)
    else:
        assert isinstance(dec.details[detail], list)



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
def test_get_decoders_file_status(status, func, open_mock):
    """
    Tests getting decoders using status filter
    """
    if status == 'random':
        with pytest.raises(WazuhException, match='.* 1202 .*'):
            func(status=status)
    else:
        with patch('builtins.open', open_mock):
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
def test_get_decoders_file_path(path, func, open_mock):
    """
    Tests getting decoders files filtering by path
    """
    with patch('builtins.open', open_mock):
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
def test_get_decoders_file_pagination(offset, limit, func, open_mock):
    """
    Tests getting decoders files using offset and limit
    """
    if limit > 0:
        with patch('builtins.open', open_mock):
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
def test_get_decoders_file_sort(sort, func, open_mock):
    """
    Tests getting decoders files and sorting results
    """
    with patch('builtins.open', open_mock):
        d_files = func(sort=sort)
        if isinstance(d_files['items'][0], Decoder):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if sort is not None:
            assert d_files['items'][0]['file'] == f"decoders{'0' if sort['order'] == 'asc' else '1'}.xml"


@pytest.mark.parametrize('search', [
    None,
    {"value": "1", "negation": 0},
    {"value": "1", "negation": 1}
])
def test_get_decoders_file_search(search, open_mock):
    """
    Tests getting decoders files and searching results
    """
    with patch('builtins.open', open_mock):
        d_files = Decoder.get_decoders_files(search=search)
        if isinstance(d_files['items'][0], Decoder):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if search is not None:
            assert d_files['items'][0]['file'] == f"decoders{'0' if search['negation'] else '1'}.xml"


@patch('wazuh.configuration.get_ossec_conf', return_value=None)
def test_private_get_files_empty_conf(*mocked_args):
    """
    Tests empty ossec.conf section exception
    """
    with pytest.raises(WazuhException, match='.* 1500 .*'):
        Decoder.get_decoders_files()


@pytest.mark.parametrize('mock_conf', [
    {
        'decoder_dir': ['ruleset/decoders'],
        'decoder_include': ['decoders1.xml'],
    },
    {
        'decoder_dir': 'ruleset/decoders',
        'decoder_include': 'decoders1.xml',
    }
])
def test_private_get_files_list_conf(mock_conf):
    """
    Tests with decoder_dir as a list and as a string, also with decoder_include
    """
    with patch('wazuh.configuration.get_ossec_conf', return_value=mock_conf):
        result = Decoder.get_decoders_files(file='mock.xml')
        assert isinstance(result, dict)


@pytest.mark.parametrize('name', [
    None,
    'random',
    'agent-buffer'
])
@pytest.mark.parametrize('file', [
    None,
    'random',
    'decoders1.xml'
])
def test_get_decoders_name(name, file, open_mock):
    """
    Tests getting decoders by name and file filtering
    """
    with patch('builtins.open', open_mock):
        result = Decoder.get_decoders(name=name, search=mock_search, file=file)
        if name == 'agent-buffer' and file == 'decoders1.xml':
            assert result['items'][0].name == 'agent-buffer'
        else:
            assert isinstance(result, dict)


def test_get_decoders_parents(open_mock):
    """
    Tests getting parent decoders
    """
    with patch('builtins.open', open_mock):
        result = Decoder.get_decoders(parents=True)
        assert isinstance(result, dict)


def test_private_load_decoders_from_file(open_mock):
    """
    Tests_load_decoders_from_file
    """
    with patch('builtins.open', open_mock):
        result = Decoder.get_decoders()

        assert isinstance(result, dict)


@patch('wazuh.decoder.load_wazuh_xml', side_effect=Exception)
def test_private_load_decoders_from_file_exceptions(mock_load):
    """
    Tests exceptions for load wazuh xml
    """
    with pytest.raises(WazuhException, match='.* 1501 .*'):
        Decoder.get_decoders()