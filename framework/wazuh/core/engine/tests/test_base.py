from unittest import mock

import pytest
from httpx import AsyncClient, ConnectError, HTTPStatusError, Timeout, TimeoutException, UnsupportedProtocol
from wazuh.core.engine.base import BaseModule, DEFAULT_TIMEOUT
from wazuh.core.exception import WazuhEngineError


def test_base_module_init():
    """Check the correct initialization of the `BaseModule` class."""

    client_mock = mock.MagicMock()
    instance = BaseModule(client=client_mock)

    assert instance._client == client_mock


@pytest.mark.asyncio
async def test_base_module_send_success():
    """Validate successful `send` method execution."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    
    # Mock successful response
    mock_response = mock.Mock()
    mock_response.json.return_value = {'status': 'success', 'data': 'test_data'}
    mock_response.raise_for_status.return_value = None
    client_mock.post.return_value = mock_response
    
    result = await module.send('/test/path', {'key': 'value'})
    
    # Verify the request was made correctly
    client_mock.post.assert_called_once_with(
        url='http://localhost/test/path',
        json={'key': 'value'},
        timeout=Timeout(DEFAULT_TIMEOUT)
    )
    mock_response.raise_for_status.assert_called_once()
    mock_response.json.assert_called_once()
    
    assert result == {'status': 'success', 'data': 'test_data'}


@pytest.mark.asyncio
@pytest.mark.parametrize('exception_class,error_code', [
    (TimeoutException, 2800),
    (UnsupportedProtocol, 2800),
    (ConnectError, 2800),
])
async def test_base_module_send_connection_errors(exception_class, error_code):
    """Validate that `send` method connection-related exceptions are properly handled."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    
    # Mock the exception
    client_mock.post.side_effect = exception_class('Test error')
    
    with pytest.raises(WazuhEngineError, match=f'.*{error_code}.*'):
        await module.send('test/path', {'key': 'value'})


@pytest.mark.asyncio
async def test_base_module_send_http_error():
    """Validate that `send` method HTTP errors are properly handled."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    
    # Create a mock response for HTTPStatusError
    mock_request = mock.Mock()
    mock_response = mock.Mock()
    mock_response.status_code = 500
    
    # Mock HTTPStatusError (which is a subclass of HTTPError)
    http_error = HTTPStatusError('Server error', request=mock_request, response=mock_response)
    client_mock.post.side_effect = http_error
    
    with pytest.raises(WazuhEngineError, match='.*2803.*'):
        await module.send('test/path', {'key': 'value'})


@pytest.mark.asyncio
async def test_base_module_send_generic_exception():
    """Validate that `send` method generic exceptions are properly handled."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    
    # Mock a generic exception
    client_mock.post.side_effect = Exception('Generic error')
    
    with pytest.raises(WazuhEngineError, match='.*2804.*'):
        await module.send('test/path', {'key': 'value'})


@pytest.mark.asyncio
async def test_base_module_send_json_decode_error():
    """Validate that `send` method JSON decode errors are properly handled."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    
    # Mock successful HTTP response but invalid JSON
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = ValueError('Invalid JSON')
    mock_response.text = 'Invalid JSON response'
    client_mock.post.return_value = mock_response
    
    with pytest.raises(WazuhEngineError, match='.*2805.*'):
        await module.send('test/path', {'key': 'value'})
    
    assert mock_response.text == 'Invalid JSON response'


@pytest.mark.asyncio
async def test_base_module_send_http_status_error():
    """Validate that `send` method HTTP status errors (4xx, 5xx) trigger raise_for_status and are handled."""
    client_mock = mock.AsyncMock()
    module = BaseModule(client=client_mock)
    
    # Mock response that raises HTTPStatusError on raise_for_status()
    mock_response = mock.Mock()
    mock_response.raise_for_status.side_effect = HTTPStatusError(
        'Bad Request', 
        request=mock.Mock(), 
        response=mock.Mock(status_code=400)
    )
    client_mock.post.return_value = mock_response
    
    with pytest.raises(WazuhEngineError, match='.*2803.*'):
        await module.send('test/path', {'key': 'value'})
    
    mock_response.raise_for_status.assert_called_once()
