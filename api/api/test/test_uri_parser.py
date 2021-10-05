from unittest.mock import MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionRequest

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from api.uri_parser import APIUriParser


@patch('api.uri_parser.APIUriParser.resolve_query')
@patch('api.uri_parser.APIError')
@patch('api.uri_parser.raise_if_exc')
@pytest.mark.parametrize('mock_parse_return, mock_q',
                         [
                             (';', True),
                             ('mock_parse_return_value', False),
                             ('mock_parse_return_value', True)
                             ]
                         )
def test_apiuriparser_call(mock_exc, mock_aerror, mock_rquery, mock_parse_return, mock_q):
    with patch('api.uri_parser.parse_api_param', return_value=mock_parse_return) as mock_parse:
        QUERY_DICT = {'q': 'q_value', 'status': 'StAtUs_Value'} if mock_q else {'status': 'StAtUs_ValuE'}

        uri_parser = APIUriParser({}, {})
        function = MagicMock()
        request = ConnexionRequest('url_value',
                                   'method_value',
                                   query=QUERY_DICT
                                   )

        result = uri_parser(function)(request)
        if mock_q:
            mock_parse.assert_called_once_with(request.url, 'q')
            if mock_parse_return == ';':
                mock_exc.assert_called_once_with(mock_aerror.return_value)
                mock_aerror.assert_called_once_with(code=2009)
            mock_rquery.assert_called_once_with({'q': 'q_value', 'status': 'status_value'})
        else:
            mock_rquery.assert_called_once_with({'status': 'status_value'})
        assert result == function.return_value
        function.assert_called_once_with(request)
