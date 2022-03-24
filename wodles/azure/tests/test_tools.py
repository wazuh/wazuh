import os

import json
import pytest
import sys

from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
import tools

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_last_dates_path = os.path.join(test_data_path, 'last_date_files')


@pytest.mark.parametrize('last_dates_file_path', [
    (os.path.join(test_last_dates_path, 'last_dates.json')),
    (os.path.join(test_last_dates_path, 'last_dates_graph.json')),
    (os.path.join(test_last_dates_path, 'last_dates_log_analytics.json')),
    (os.path.join(test_last_dates_path, 'last_dates_storage.json')),
    (os.path.join(test_last_dates_path, 'last_dates_old.json')),
    (os.path.join(test_last_dates_path, 'last_dates_clean.json'))
])
def test_load_dates_json(last_dates_file_path):
    with patch('tools.last_dates_path', new=last_dates_file_path):
        last_dates_dict = tools.load_dates_json()
        for key in last_dates_dict.keys():
            assert isinstance(last_dates_dict[key], dict)
            for md5 in last_dates_dict[key].keys():
                assert isinstance(last_dates_dict[key][md5], dict)
                assert set(last_dates_dict[key][md5].keys()) == {'min', 'max'}


@patch('os.path.exists', return_value=False)
@patch('builtins.open')
@patch('json.dump')
def test_load_dates_json_no_file(mock_dump, mock_open, mock_exists):
    tools.load_dates_json()
    mock_exists.assert_called_once()
    mock_open.assert_called_once()
    mock_dump.assert_called_once_with(tools.last_dates_default_contents, mock_open().__enter__())


@pytest.mark.parametrize('last_dates_file_path', [
    (os.path.join(test_last_dates_path, 'last_dates_invalid.json'))
])
def test_load_dates_json_ko(last_dates_file_path):
    with patch('tools.last_dates_path', new=last_dates_file_path):
        with pytest.raises(json.JSONDecodeError):
            tools.load_dates_json()
