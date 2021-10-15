from unittest.mock import MagicMock, patch

import pytest
from api.api_exception import APIError
from connexion.lifecycle import ConnexionRequest

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from api.uri_parser import APIUriParser

QUERY_DICT = {'component': 'VaLuE',
              'configuration': 'VaLuE',
              'hash': 'VaLuE',
              'requirement': 'VaLuE',
              'status': 'VaLuE',
              'type': 'VaLuE',
              'section': 'VaLuE',
              'tag': 'VaLuE',
              'level': 'VaLuE',
              'resource': 'VaLuE0',
              'q': ''
              }
QUERY_DICT_Q = QUERY_DICT.copy()
QUERY_DICT_Q['q'] = 'q=value'
QUERY_DICT_Q_SC = QUERY_DICT.copy()
QUERY_DICT_Q_SC['q'] = 'q=;'


@pytest.mark.parametrize('query_value',
                         [
                             (QUERY_DICT),
                             (QUERY_DICT_Q),
                             (QUERY_DICT_Q_SC)
                             ]
                         )
def test_apiuriparser_call(query_value):
    uri_parser = APIUriParser({}, {})
    function = MagicMock()
    request = ConnexionRequest(url=query_value['q'],
                               method='method_value',
                               query=query_value
                               )
    expected_request = ConnexionRequest(url=query_value['q'],
                                        method='method_value',
                                        query=dict((k, v.lower()) for k, v in query_value.items())
                                        )
    # uri_parser(function)(request):
    # Its calling __call__ class method. We're parametrizing the wrapper with the second parameter between brackets.
    if ';' in query_value['q']:
        with pytest.raises(APIError, match='2009 .*'):
            uri_parser(function)(request)
    else:
        uri_parser(function)(request)
        assert request.query == expected_request.query
