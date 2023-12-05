# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionRequest

from api.api_exception import APIError

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from api.uri_parser import APIUriParser

query_dict = {'component': 'VaLuE',
              'configuration': 'VaLuE',
              'hash': 'VaLuE',
              'requirement': 'VaLuE',
              'status': 'VaLuE',
              'type': 'VaLuE',
              'section': 'VaLuE',
              'tag': 'VaLuE',
              'level': 'VaLuE',
              'resource': 'VaLuE'
              }
LOWER_FIELDS = ['component', 'configuration', 'hash', 'requirement', 'status', 'type', 'section', 'tag',
                'level', 'resource']


@pytest.mark.parametrize('q_value',
                         [
                             '',
                             'q=value',
                             'q=;'
                             ]
                         )
def test_apiuriparser_call(q_value):
    query_dict.update({'q': q_value})
    uri_parser = APIUriParser({}, {})
    function = MagicMock()
    request = ConnexionRequest(url=q_value,
                               method='method_value',
                               query=query_dict
                               )
    expected_request = ConnexionRequest(url=q_value,
                                        method='method_value',
                                        query={k: v.lower() if k in LOWER_FIELDS else v for k, v in query_dict.items()}
                                        )
    # uri_parser(function)(request):
    # It's calling the __call__ class method.
    # The wrapper is being parametrized by the second parameter between brackets.
    if ';' in q_value:
        with pytest.raises(APIError, match='2009 .*'):
            uri_parser(function)(request)
    else:
        uri_parser(function)(request)
        assert request.query == expected_request.query
