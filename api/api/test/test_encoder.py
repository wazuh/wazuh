from unittest.mock import ANY, MagicMock, patch

import pytest

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from api.encoder import WazuhJSONEncoder, dumps, prettify
        from wazuh.core.results import AbstractWazuhResult

SAMPLE_DICT = {'k1': 'v1', 'k2': 'v2'}


@pytest.mark.parametrize('mock_method', ['default', 'model', 'abtractwazuhresult'])
def test_wjson_encoder(mock_method):
    wjson_encoder = WazuhJSONEncoder()
    assert wjson_encoder.include_nulls is False
    mock_obj = AbstractWazuhResult({}) if mock_method == 'abtractwazuhresult' else MagicMock()

    if mock_method == 'default':
        with patch('api.encoder.isinstance', return_value=False):
            with patch('api.encoder.JSONEncoder.default', return_value=SAMPLE_DICT) as mock_default:
                result = wjson_encoder.default(mock_obj)
                assert result == mock_default.return_value
                mock_default.assert_called_once_with(wjson_encoder, mock_obj)
    elif mock_method == 'model':
        with patch('api.encoder.Model', new=MagicMock):
            with patch('api.encoder.six.iteritems', return_value=SAMPLE_DICT.items()) as mock_iter:
                mock_obj.attribute_map = SAMPLE_DICT
                mock_obj.k1 = 'v3'
                mock_obj.k2 = None
                result = wjson_encoder.default(mock_obj)
                assert result == {'v1': 'v3'}
                mock_iter.assert_called_once_with(mock_obj.swagger_types)
    elif mock_method == 'abtractwazuhresult':
        with patch('wazuh.core.results.AbstractWazuhResult.render', return_value=SAMPLE_DICT) as mock_render:
            result = wjson_encoder.default(mock_obj)
            assert result == mock_render.return_value
            mock_render.assert_called_once_with()


@pytest.mark.parametrize('mock_method', [dumps, prettify])
def test_wjson_method(mock_method):
    with patch('api.encoder.WazuhJSONEncoder') as mock_wjsonencoder:
        with patch('api.encoder.json.dumps', return_value=f'{SAMPLE_DICT}') as mock_jsondumps:
            result = mock_method({})
            assert result == mock_jsondumps.return_value
            mock_jsondumps.assert_called_once_with({}, cls=mock_wjsonencoder) if mock_method == dumps \
                else mock_jsondumps.assert_called_once_with({}, cls=mock_wjsonencoder, indent=ANY)
