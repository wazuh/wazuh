from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from freezegun import freeze_time
from wazuh.core.exception import WazuhIndexerError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.indexer.models.agent import Agent, Status
from wazuh.core.utils import get_utc_now

from comms_api.models.authentication import Credentials, TokenResponse
from comms_api.routers.authentication import authentication
from comms_api.routers.exceptions import HTTPError


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1))
@patch('wazuh.core.indexer.Indexer._get_opensearch_client', new_callable=AsyncMock)
@patch('wazuh.core.indexer.Indexer.connect')
@patch('wazuh.core.indexer.Indexer.close')
@patch('wazuh.core.indexer.agent.AgentsIndex.get')
@patch('wazuh.core.indexer.agent.AgentsIndex.update')
@patch('comms_api.routers.authentication.generate_token', return_value='token')
async def test_authentication(
    generate_token_mock,
    agents_index_update_mock,
    agents_index_get_mock,
    close_mock,
    connect_mock,
    get_opensearch_client_mock,
):
    """Verify that the `authentication` handler works as expected."""
    uuid = '0'
    credentials = Credentials(uuid=uuid, key='key')
    response = await authentication(credentials)
    
    get_opensearch_client_mock.assert_called_once()
    connect_mock.assert_called_once()
    close_mock.assert_called_once()
    agents_index_get_mock.assert_called_once_with(uuid)
    agents_index_update_mock.assert_called_once_with(uuid, Agent(last_login=get_utc_now(), status=Status.ACTIVE))
    generate_token_mock.assert_called_once_with(credentials.uuid)
    assert response == TokenResponse(token='token')

@pytest.mark.asyncio
@pytest.mark.parametrize('exception,message', [
    (WazuhIndexerError(2200), 'Couldn\'t connect to the indexer: Error 2200 - Could not connect to the indexer'),
    (WazuhResourceNotFound(1701), 'Agent does not exist'),
    (WazuhInternalError(6003), 'Couldn\'t get key pair: Error 6003 - Error trying to load the JWT secret'),
])
async def test_authentication_ko(exception, message):
    """Verify that the `authentication` handler catches exceptions successfully."""
    with patch('wazuh.core.indexer.create_indexer', AsyncMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{status.HTTP_403_FORBIDDEN}: {message}'):
            _ = await authentication(Credentials(uuid='', key=''))
