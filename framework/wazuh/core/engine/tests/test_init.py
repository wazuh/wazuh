from unittest import mock

import pytest
from httpx import AsyncClient, ConnectError, HTTPStatusError, Response, Timeout, TimeoutException, UnsupportedProtocol
from wazuh.core.engine import DEFAULT_RETRIES, DEFAULT_TIMEOUT, Engine, get_engine_client
from wazuh.core.exception import WazuhEngineError


@pytest.mark.parametrize(
    'params',
    [
        {'retries': 3, 'timeout': 10},
        {'retries': None, 'timeout': 15},
        {'timeout': 0},
        {},
    ],
)
def test_engine_init(params: dict):
    """Check the correct initialization of the `Engine` class."""
    engine = Engine(socket_path='/test.sock', **params)

    assert isinstance(engine._client, AsyncClient)
    assert not engine._client.is_closed

    if 'retries' in params:
        assert engine._client._transport._pool._retries == params['retries']
    else:
        assert engine._client._transport._pool._retries == DEFAULT_RETRIES

    if 'timeout' in params:
        assert engine._client.timeout == Timeout(params['timeout'])
    else:
        assert engine._client.timeout == Timeout(DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_engine_close():
    """Check the correct functionality of the `close` method."""
    engine = Engine(socket_path='/test.sock', retries=5, timeout=10)
    engine._client = mock.AsyncMock()
    await engine.close()

    engine._client.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_get_engine_client():
    """Check the correct behavior of the `get_engine_client` function."""
    async with get_engine_client() as engine:
        assert not engine._client.is_closed

    assert engine._client.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize('socket_path,error_number', [
    ('http://timeout', 2800),
    ('test', 2801),
    ('http://invalid', 2802),
])
async def test_get_engine_client_ko(socket_path: str, error_number: int):
    """Check that the `get_engine_client` returns a WazuhEngineError on an exception."""
    with pytest.raises(WazuhEngineError, match=f'.*{error_number}.*'):
        async with get_engine_client() as engine:
            engine._client._transport._pool._retries = 0
            engine._client.timeout = Timeout(None)

            if error_number == 2800:
                engine._client = mock.AsyncMock()
                engine._client.get.side_effect = TimeoutException('')

            _ = await engine._client.get(socket_path)


@pytest.mark.asyncio
async def test_engine_send_success():
    """Test successful send method execution."""
    engine = Engine()
    engine._client = mock.AsyncMock()
    
    # Mock successful response
    mock_response = mock.Mock()
    mock_response.json.return_value = {'status': 'success', 'data': 'test_data'}
    mock_response.raise_for_status.return_value = None
    engine._client.post.return_value = mock_response
    
    result = await engine.send('test/path', {'key': 'value'})

    engine._client.post.assert_called_once_with(
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
async def test_engine_send_connection_error(exception_class, error_code):
    """Test that connection-related exceptions are properly handled."""
    engine = Engine()
    engine._client = mock.AsyncMock()
    
    # Mock the exception
    engine._client.post.side_effect = exception_class('Test error')
    
    with pytest.raises(WazuhEngineError, match=f'.*{error_code}.*'):
        await engine.send('test/path', {'key': 'value'})


@pytest.mark.asyncio
async def test_engine_send_http_error():
    """Test that HTTP errors are properly handled."""
    engine = Engine()
    engine._client = mock.AsyncMock()
    
    # Create a mock response for HTTPStatusError
    mock_request = mock.Mock()
    mock_response = mock.Mock()
    mock_response.status_code = 500
    
    # Mock HTTPStatusError (which is a subclass of HTTPError)
    http_error = HTTPStatusError('Server error', request=mock_request, response=mock_response)
    engine._client.post.side_effect = http_error
    
    with pytest.raises(WazuhEngineError, match='.*2803.*'):
        await engine.send('test/path', {'key': 'value'})


@pytest.mark.asyncio
async def test_engine_send_generic_exception():
    """Test that generic exceptions are properly handled."""
    engine = Engine()
    engine._client = mock.AsyncMock()
    
    # Mock a generic exception
    engine._client.post.side_effect = Exception('Generic error')
    
    with pytest.raises(WazuhEngineError, match='.*2804.*'):
        await engine.send('test/path', {'key': 'value'})


@pytest.mark.asyncio
async def test_engine_send_json_decode_error():
    """Test that JSON decode errors are properly handled."""
    engine = Engine()
    engine._client = mock.AsyncMock()
    
    # Mock successful HTTP response but invalid JSON
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = ValueError('Invalid JSON')
    mock_response.text = 'Invalid JSON response'
    engine._client.post.return_value = mock_response
    
    with pytest.raises(WazuhEngineError, match='.*2805.*'):
        await engine.send('test/path', {'key': 'value'})

    assert mock_response.text == 'Invalid JSON response'


@pytest.mark.asyncio
async def test_engine_send_http_status_error():
    """Test that HTTP status errors (4xx, 5xx) trigger raise_for_status and are handled."""
    engine = Engine()
    engine._client = mock.AsyncMock()
    
    # Mock response that raises HTTPStatusError on raise_for_status()
    mock_response = mock.Mock()
    mock_response.raise_for_status.side_effect = HTTPStatusError(
        'Bad Request', 
        request=mock.Mock(), 
        response=mock.Mock(status_code=400)
    )
    engine._client.post.return_value = mock_response
    
    with pytest.raises(WazuhEngineError, match='.*2803.*'):
        await engine.send('test/path', {'key': 'value'})

    mock_response.raise_for_status.assert_called_once()
