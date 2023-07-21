import pytest
from unittest.mock import patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.engine import ENGINE, get_graph_resource


@pytest.mark.parametrize('policy, graph_type, expected_result', [
    ('policy', 'graph_type', {'policy': 'policy', 'type': 'type'}),
    None,
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_get_graph_resource(policy, graph_type, expected_result):
    response = get_graph_resource(policy=policy, graph_type=graph_type)
    assert response['status'] == 'OK'
    assert response['error'] is None
    assert response['content'] == expected_result


# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_get_graph_resource_ko():
    response = get_graph_resource(policy='non-existent', graph_type='')
    assert response['status'] == 'ERROR'
    assert response['error'] == 'The specified graph resource does not exist'
    assert response['content'] is None
