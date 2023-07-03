import pytest
from unittest.mock import patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.engine import ENGINE, add_catalog_resource, delete_catalog_resource, get_catalog_resource, \
        update_catalog_resource, validate_catalog_resource


@pytest.mark.parametrize('resource_type, resource_format, content', [
    ('policy', 'json', "{'content': 'test'}"),
    ('schema', 'yaml', 'content: test'),
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_add_catalog_resource(resource_type, resource_format, content):
    got_content = add_catalog_resource(resource_type, resource_format, content)
    assert got_content == {'status': 'OK', 'error': None}


@pytest.mark.parametrize('name', [
    'test',
    None,
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_delete_catalog_resource(name):
    response = delete_catalog_resource(name)
    assert response['status'] == 'OK'
    assert response['error'] is None


@pytest.mark.parametrize('name, resource_type', [
    ('test', 'filter'),
    (None, None),
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_get_catalog_resource(name, resource_type):
    if name is not None:
        content = 'mockContent'
        add_catalog_resource(name, content, False)

    response = get_catalog_resource(name, resource_type)
    assert response['status'] == 'OK'
    assert response['error'] is None
    if name is not None:
        assert response['content'] == content
    else:
        assert response['content'] == '{"test": "mockContent"}'


@pytest.mark.parametrize('name, resource_type, content', [
    ('test', 'rule', 'sample_rule'),
    ('test', 'decoder', 'sample_decoder'),
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_update_catalog_resource(name, content, save):
    content = update_catalog_resource(name, content, save)
    assert content == {'status': 'OK', 'error': None}


@pytest.mark.parametrize('name, resource_type, content', [
    ('valid', 'rule', 'content'),
    ('invalid', 'integratio', 'content'),
])
# @patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=b'"{\'test\':\'test\'}"')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.send')
# @patch('wazuh.core.wazuh_socket.WazuhSocket.close')
def test_validate_catalog_resource(name, resource_type, content):
    content = validate_catalog_resource(name, resource_type, content)
    assert content == {'status': 'OK', 'error': None}
