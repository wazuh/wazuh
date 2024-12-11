from unittest import mock

import pytest
from httpx import AsyncClient, Timeout, TimeoutException
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
