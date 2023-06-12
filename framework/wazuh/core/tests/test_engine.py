import pytest
import json
import os
from unittest.mock import patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.engine import ENGINE, get_runtime_config, update_runtime_config, parse_content


@pytest.mark.parametrize('name', [
    'test',
    None,
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_get_runtime_config(name):
    if name is not None:
        content = 'mockContent'
        update_runtime_config(name, content, False)

    response = get_runtime_config(name)
    assert response['status'] == 'OK'
    assert response['error'] == None
    if name is not None:
        assert response['content'] == content
    else:
        assert response['content'] == '{"test": "mockContent"}'


@pytest.mark.parametrize('name, content, save', [
    ('test', 'content', False),
    ('test', 'saved_content', True),
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_update_runtime_config(name, content, save):
    if save:
        ENGINE.path = 'test_conf'

    content = update_runtime_config(name, content, save)
    assert content == {'status': 'OK', 'error': None}

    if save:
        assert os.path.exists(ENGINE.path)
        with open(ENGINE.path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            assert data == ENGINE.configs
        os.remove(ENGINE.path)

@pytest.mark.parametrize('content, expected_content', [
    (
        '\n# Sets the logging level.\nserver.log_level="error"\n\n',
        '{"server": {"log_level": "error"}}',
    ),
    (
        'server.router_threads=1\n\nserver.queue_size=10000',
        '{"server": {"router_threads": 1, "queue_size": 10000}}',
    ),
])
def test_parse_content(content, expected_content):
    got_content = parse_content(content)
    assert got_content == expected_content