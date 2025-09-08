from unittest import mock

import pytest
from httpx import ConnectError, HTTPStatusError, Timeout, TimeoutException, UnsupportedProtocol
from wazuh.core.engine.base import BaseModule, DEFAULT_TIMEOUT
from wazuh.core.exception import WazuhEngineError


def test_base_module_init():
    """Check the correct initialization of the `BaseModule` class."""

    client_mock = mock.MagicMock()
    instance = BaseModule(client=client_mock)

    assert instance._client == client_mock

@pytest.mark.asyncio
async def test_base_module_get_success():
    """Validate successful `get` method execution."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)

    mock_response = mock.Mock()
    mock_response.json.return_value = {'status': 'success', 'data': 'test_data'}
    mock_response.raise_for_status.return_value = None
    client_mock.get.return_value = mock_response

    result = await module.get('/test/path', {'param': 'value'})

    client_mock.get.assert_called_once_with(
        url='http://localhost/test/path',
        params={'param': 'value'},
        timeout=Timeout(DEFAULT_TIMEOUT)
    )
    mock_response.raise_for_status.assert_called_once()
    mock_response.json.assert_called_once()
    assert result == {'status': 'success', 'data': 'test_data'}


@pytest.mark.asyncio
async def test_base_module_put_success():
    """Validate successful `put` method execution."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)

    mock_response = mock.Mock()
    mock_response.json.return_value = {'status': 'success', 'data': 'test_data'}
    mock_response.raise_for_status.return_value = None
    client_mock.put.return_value = mock_response

    result = await module.put('/test/path', {'key': 'value'})

    client_mock.put.assert_called_once_with(
        url='http://localhost/test/path',
        json={'key': 'value'},
        timeout=Timeout(DEFAULT_TIMEOUT)
    )
    mock_response.raise_for_status.assert_called_once()
    mock_response.json.assert_called_once()
    assert result == {'status': 'success', 'data': 'test_data'}


@pytest.mark.asyncio
async def test_base_module_delete_success():
    """Validate successful `delete` method execution."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)

    mock_response = mock.Mock()
    mock_response.json.return_value = {'status': 'success', 'data': 'test_data'}
    mock_response.raise_for_status.return_value = None
    client_mock.delete.return_value = mock_response

    result = await module.delete('/test/path', {'param': 'value'})

    client_mock.delete.assert_called_once_with(
        url='http://localhost/test/path',
        params={'param': 'value'},
        timeout=Timeout(DEFAULT_TIMEOUT)
    )
    mock_response.raise_for_status.assert_called_once()
    mock_response.json.assert_called_once()
    assert result == {'status': 'success', 'data': 'test_data'}


@pytest.mark.asyncio
@pytest.mark.parametrize('method,client_method,exception_class,error_code', [
    ('get', 'get', TimeoutException, 2800),
    ('get', 'get', UnsupportedProtocol, 2800),
    ('get', 'get', ConnectError, 2800),
    ('put', 'put', TimeoutException, 2800),
    ('put', 'put', UnsupportedProtocol, 2800),
    ('put', 'put', ConnectError, 2800),
    ('delete', 'delete', TimeoutException, 2800),
    ('delete', 'delete', UnsupportedProtocol, 2800),
    ('delete', 'delete', ConnectError, 2800),
])
async def test_base_module_methods_connection_errors(method, client_method, exception_class, error_code):
    """Validate connection-related exceptions for get, put, and delete methods."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    getattr(client_mock, client_method).side_effect = exception_class('Test error')

    with pytest.raises(WazuhEngineError, match=f'.*{error_code}.*'):
        if method == 'get':
            await module.get('test/path', {'param': 'value'})
        elif method == 'put':
            await module.put('test/path', {'key': 'value'})
        elif method == 'delete':
            await module.delete('test/path', {'param': 'value'})


@pytest.mark.asyncio
@pytest.mark.parametrize('method,client_method', [
    ('get', 'get'),
    ('put', 'put'),
    ('delete', 'delete'),
])
async def test_base_module_methods_http_error(method, client_method):
    """Validate HTTP errors for get, put, and delete methods."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    mock_request = mock.Mock()
    mock_response = mock.Mock()
    mock_response.status_code = 500
    http_error = HTTPStatusError('Server error', request=mock_request, response=mock_response)
    getattr(client_mock, client_method).side_effect = http_error

    with pytest.raises(WazuhEngineError, match='.*2803.*'):
        if method == 'get':
            await module.get('test/path', {'param': 'value'})
        elif method == 'put':
            await module.put('test/path', {'key': 'value'})
        elif method == 'delete':
            await module.delete('test/path', {'param': 'value'})


@pytest.mark.asyncio
@pytest.mark.parametrize('method,client_method', [
    ('get', 'get'),
    ('put', 'put'),
    ('delete', 'delete'),
])
async def test_base_module_methods_generic_exception(method, client_method):
    """Validate generic exceptions for get, put, and delete methods."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    getattr(client_mock, client_method).side_effect = Exception('Generic error')

    with pytest.raises(WazuhEngineError, match='.*2804.*'):
        if method == 'get':
            await module.get('test/path', {'param': 'value'})
        elif method == 'put':
            await module.put('test/path', {'key': 'value'})
        elif method == 'delete':
            await module.delete('test/path', {'param': 'value'})


@pytest.mark.asyncio
@pytest.mark.parametrize('method,client_method', [
    ('get', 'get'),
    ('put', 'put'),
    ('delete', 'delete'),
])
async def test_base_module_methods_json_decode_error(method, client_method):
    """Validate JSON decode errors for get, put, and delete methods."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = ValueError('Invalid JSON')
    mock_response.text = 'Invalid JSON response'
    getattr(client_mock, client_method).return_value = mock_response

    with pytest.raises(WazuhEngineError, match='.*2805.*'):
        if method == 'get':
            await module.get('test/path', {'param': 'value'})
        elif method == 'put':
            await module.put('test/path', {'key': 'value'})
        elif method == 'delete':
            await module.delete('test/path', {'param': 'value'})

    assert mock_response.text == 'Invalid JSON response'
