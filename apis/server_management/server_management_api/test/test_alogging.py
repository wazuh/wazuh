# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from copy import copy
from unittest.mock import patch, call, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from server_management_api import alogging

REQUEST_HEADERS_TEST = {'authorization': 'Basic d2F6dWg6cGFzc3dvcmQxMjM='}  # wazuh:password123
AUTH_CONTEXT_TEST = {'auth_context': 'example'}
HASH_AUTH_CONTEXT_TEST = '020efd3b53c1baf338cf143fad7131c3'


@pytest.mark.parametrize("path, hash_auth_context, body, loggerlevel", [
    ("/agents", '', {'bodyfield': 1}, 1),
    ("/agents", 'hashauthcontext', {'bodyfield': 1}, 21),
    ("/events", '', {'bodyfield': 1, 'events' : [{'a': 1, 'b': 2 }]}, 1),
    ("/events", 'hashauthcontext', {'bodyfield': 1, 'events' : [{'a': 1, 'b': 2 }]}, 22),
    ("/events", 'hashauthcontext', ['foo', 'bar'], 22),
    ("/events", 'hashauthcontext', 'foo', 22),
])
def test_custom_logging(path, hash_auth_context, body, loggerlevel):
    """Test custom access logging calls."""
    user, remote, method = ('wazuh', '1.1.1.1', 'POST')
    query, elapsed_time, status, headers =  {'pretty': True}, 1.01, 200, {'content-type': 'xml'}
    json_info = {
        'user': user,
        'ip': remote,
        'http_method': method,
        'uri': f'{method} {path}',
        'parameters': query,
        'body': body,
        'time': f'{elapsed_time:.3f}s',
        'status_code': status
    }

    log_info = f'{user} ({hash_auth_context}) {remote} "{method} {path}" ' if hash_auth_context \
                else f'{user} ({hash_auth_context}) {remote} "{method} {path}" '
    json_info.update({'hash_auth_context' : hash_auth_context} if hash_auth_context else {})
    with patch('api.alogging.logger') as log_info_mock:
        log_info_mock.info = MagicMock()
        log_info_mock.debug2 = MagicMock()
        log_info_mock.level = loggerlevel
        alogging.custom_logging(user=user, remote=remote, method=method, path=path, query=query,
                        body=copy(body), elapsed_time=elapsed_time, status=status,
                        hash_auth_context=hash_auth_context, headers=headers)

        if path == '/events' and loggerlevel >= 20:
            if isinstance(body, dict):
                events = body.get('events', [])
                body = {'events': len(events)}
                json_info['body'] = body
        log_info += f'with parameters {json.dumps(query)} and body'\
                    f' {json.dumps(body)} done in {elapsed_time:.3f}s: {status}'
        log_info_mock.info.has_calls([call(log_info, {'log_type': 'log'}),
                                      call(json_info, {'log_type': 'json'})])
        log_info_mock.debug2.assert_called_with(f'Receiving headers {headers}')
