import pytest
from unittest.mock import patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.engine import add_integration_policy, remove_integration_policy


@pytest.mark.parametrize('policy, integration', [
    ('test_policy', 'test_integration')
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_add_integration_policy(policy, integration):
    resp = add_integration_policy(policy, integration)
    assert resp == {'status': 'OK', 'error': None}


@pytest.mark.parametrize('policy, integration', [
    ('test_policy', 'test_integration')
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_remove_integration_policy(policy, integration):
    resp = remove_integration_policy(policy, integration)
    assert resp == {'status': 'OK', 'error': None}