from datetime import datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from aiohttp import ClientError

import wazuh
from wazuh.core.requests import (
    RELEASE_UPDATES_URL,
    WAZUH_TAG_KEY,
    WAZUH_UID_KEY,
    get_update_information_template,
    query_update_check_service,
)

# Fixtures


@pytest.fixture
def client_session_get_mock():
    with patch('aiohttp.ClientSession.get') as get_mock:
        yield get_mock


@pytest.fixture
def installation_uid():
    return str(uuid4())


# Tests

@pytest.mark.parametrize('update_check', (True, False))
@pytest.mark.parametrize('last_check_date', (None, datetime.now()))
def test_get_update_information_template(last_check_date, update_check):
    """Test that the get_update_information_template function is working properly with the given data."""

    template = get_update_information_template(update_check=update_check, last_check_date=last_check_date)

    assert 'last_check_date' in template
    assert template['last_check_date'] == (last_check_date if last_check_date is not None else '')
    assert 'update_check' in template
    assert template['update_check'] == update_check
    assert 'current_version' in template
    assert template['current_version'] == wazuh.__version__
    assert 'last_available_major' in template
    assert 'last_available_minor' in template
    assert 'last_available_patch' in template


@pytest.mark.asyncio
async def test_query_update_check_service_catch_exceptions_and_dont_raise(
    installation_uid, client_session_get_mock
):
    """Test that the query_update_check_service function handle errors correctly."""
    message_error = 'Some client error'
    client_session_get_mock.side_effect = ClientError(message_error)
    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == 500
    assert update_information['message'] == message_error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'major,minor,patch',
    (
        [['5.0.0', '5.0.1'], ['4.9.0', '4.9.1'], ['4.8.1', '4.8.2']],
        [
            ['5.0.0', '5.0.1'],
            ['4.9.0', '4.9.1'],
            [
                '4.8.1',
            ],
        ],
        [['5.0.0', '5.0.1'], ['4.9.0'], ['4.8.1', '4.8.2']],
        [['5.0.0'], ['4.9.1'], ['4.8.1']],
        [['5.0.0'], ['4.9.1'], []],
        [['5.0.0'], [], ['4.8.1']],
        [[], ['4.9.1'], ['4.8.1']],
        [[], [], []],
    ),
)
async def test_query_update_check_service_returns_correct_data_when_status_200(
    installation_uid, client_session_get_mock, major, minor, patch
):
    """Test that query_update_check_service function proccess the updates information correctly."""
    def _build_release_info(semvers: list[str]) -> list:
        release_info = []
        for semver in semvers:
            major, minor, patch = semver.split('.')
            release_info.append(
                {
                    'tag': f'v{semver}',
                    'description': 'Some description',
                    'title': f'Wazuh {semver}',
                    'published_date': '2023-09-22T10:44:00Z',
                    'semver': {'minor': minor, 'patch': patch, 'major': major},
                }
            )

        return release_info

    response_data = {
        'data': {
            'minor': _build_release_info(minor),
            'patch': _build_release_info(patch),
            'major': _build_release_info(major),
        }
    }
    status = 200

    client_session_get_mock.return_value.__aenter__.return_value.status = status
    client_session_get_mock.return_value.__aenter__.return_value.json.return_value = (
        response_data
    )

    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == status

    if len(major):
        assert (
            update_information['last_available_major']
            == response_data['data']['major'][-1]
        )
    else:
        assert update_information['last_available_major'] == {}

    if len(minor):
        assert (
            update_information['last_available_minor']
            == response_data['data']['minor'][-1]
        )
    else:
        assert update_information['last_available_minor'] == {}

    if len(patch):
        assert (
            update_information['last_available_patch']
            == response_data['data']['patch'][-1]
        )
    else:
        assert update_information['last_available_patch'] == {}


async def test_query_update_check_service_returns_correct_data_on_error(
    installation_uid, client_session_get_mock
):
    """Test that query_update_check_service function returns correct data when an error occurs."""

    response_data = {'errors': {'detail': 'Unauthorized'}}
    status = 403

    client_session_get_mock.return_value.__aenter__.return_value.status = status
    client_session_get_mock.return_value.__aenter__.return_value.json.return_value = (
        response_data
    )

    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == status
    assert update_information['message'] == response_data['errors']['detail']


@pytest.mark.asyncio
async def test_query_update_check_service_request(
    installation_uid, client_session_get_mock
):
    """Test that query_update_check_service function make request to the URL with the correct headers."""

    version = '4.8.0'
    with patch('api.signals.wazuh.__version__', version):
        await query_update_check_service(installation_uid)

        client_session_get_mock.assert_called()

        client_session_get_mock.assert_called_with(
            RELEASE_UPDATES_URL,
            headers={
                WAZUH_UID_KEY: installation_uid,
                WAZUH_TAG_KEY: f'v{version}',
            },
        )
