import asyncio
import os
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from aiohttp import ClientError

from api.signals import (
    INSTALLATION_UID_KEY,
    ONE_DAY_SLEEP,
    RELEASE_UPDATES_URL,
    UPDATE_CHECK_OSSEC_FIELD,
    WAZUH_TAG_KEY,
    WAZUH_UID_KEY,
    cancel_signal_handler,
    check_installation_uid,
    get_update_information,
    register_background_tasks,
)

# Fixtures


@pytest.fixture
def application_mock():
    return {}


@pytest.fixture
def application_mock_with_installation_uid(application_mock):
    application_mock[INSTALLATION_UID_KEY] = str(uuid4())
    return application_mock


@pytest.fixture
def installation_uid_mock():
    with patch(
        'api.signals.INSTALLATION_UID_PATH', os.path.join('/tmp', INSTALLATION_UID_KEY)
    ) as path_mock:
        yield path_mock

        os.remove(path_mock)


@pytest.fixture
def client_session_get_mock():
    with patch('aiohttp.ClientSession.get') as get_mock:
        yield get_mock

# Tests


@pytest.mark.asyncio
async def test_cancel_signal_handler_catch_cancelled_error_and_dont_rise():
    coroutine_mock = AsyncMock(side_effect=asyncio.CancelledError)
    await cancel_signal_handler(coroutine_mock)()

    coroutine_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_installation_uid_populate_uid_if_not_exists(
    installation_uid_mock, application_mock
):
    await check_installation_uid(application_mock)

    assert os.path.exists(installation_uid_mock)
    with open(installation_uid_mock) as file:
        assert application_mock[INSTALLATION_UID_KEY] == file.readline()


@pytest.mark.asyncio
async def test_check_installation_uid_get_uid_from_file(
    installation_uid_mock, application_mock
):
    installation_uid = str(uuid4())
    with open(installation_uid_mock, 'w') as file:
        file.write(installation_uid)

    await check_installation_uid(application_mock)

    assert application_mock[INSTALLATION_UID_KEY] == installation_uid


@pytest.mark.asyncio
async def test_get_update_information_catch_exceptions_and_dont_raise(
    application_mock_with_installation_uid, client_session_get_mock
):
    client_session_get_mock.side_effect = ClientError
    task = asyncio.create_task(
        get_update_information(application_mock_with_installation_uid)
    )
    await asyncio.sleep(1)
    task.cancel()
    client_session_get_mock.assert_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'major,minor,patch',
    (
        [['5.0.0', '5.0.1'], ['4.9.0', '4.9.1'], ['4.8.1', '4.8.2']],
        [['5.0.0', '5.0.1'], ['4.9.0', '4.9.1'], ['4.8.1', ]],
        [['5.0.0', '5.0.1'], ['4.9.0'], ['4.8.1', '4.8.2']],
        [['5.0.0'], ['4.9.1'], ['4.8.1']],
        [['5.0.0'], ['4.9.1'], []],
        [['5.0.0'], [], ['4.8.1']],
        [[], ['4.9.1'], ['4.8.1']],
        [[], [], []],
    ),
)
async def test_get_update_information_injects_correct_data_into_app_context_when_satatus_200(
    application_mock_with_installation_uid, client_session_get_mock, major, minor, patch
):
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
    task = asyncio.create_task(
        get_update_information(application_mock_with_installation_uid)
    )
    await asyncio.sleep(1)
    task.cancel()

    client_session_get_mock.assert_called()

    assert (
        application_mock_with_installation_uid['update_information']['status_code']
        == status
    )
    update_information = application_mock_with_installation_uid['update_information']

    if len(major):
        assert update_information['last_available_major'] == response_data['data']['major'][-1]
    else:
        assert update_information['last_available_major'] == {}

    if len(minor):
        assert update_information['last_available_minor'] == response_data['data']['minor'][-1]
    else:
        assert update_information['last_available_minor'] == {}

    if len(patch):
        assert update_information['last_available_patch'] == response_data['data']['patch'][-1]
    else:
        assert update_information['last_available_patch'] == {}


async def test_get_update_information_injects_data_into_app_context_on_error(
    application_mock_with_installation_uid, client_session_get_mock
):
    response_data = {'errors': {'detail': 'Unauthorized'}}
    status = 403

    client_session_get_mock.return_value.__aenter__.return_value.status = status
    client_session_get_mock.return_value.__aenter__.return_value.json.return_value = (
        response_data
    )
    task = asyncio.create_task(
        get_update_information(application_mock_with_installation_uid)
    )
    await asyncio.sleep(1)
    task.cancel()

    client_session_get_mock.assert_called()
    assert (
        application_mock_with_installation_uid['update_information']['status_code']
        == status
    )
    assert (
        application_mock_with_installation_uid['update_information']['message']
        == response_data['errors']['detail']
    )


@pytest.mark.asyncio
async def test_get_update_information_request(
    application_mock_with_installation_uid, client_session_get_mock
):
    version = '4.8.0'
    with patch('api.signals.wazuh.__version__', version):
        task = asyncio.create_task(
            get_update_information(application_mock_with_installation_uid)
        )
        await asyncio.sleep(1)
        task.cancel()

        client_session_get_mock.assert_called()

        client_session_get_mock.assert_called_with(
            RELEASE_UPDATES_URL,
            headers={
                WAZUH_UID_KEY: application_mock_with_installation_uid[INSTALLATION_UID_KEY],
                WAZUH_TAG_KEY: f'v{version}',
            },
        )


@pytest.mark.asyncio
async def test_get_update_information_schedule(
    application_mock_with_installation_uid, client_session_get_mock
):
    with patch('api.signals.asyncio') as sleep_mock:
        task = asyncio.create_task(
            get_update_information(application_mock_with_installation_uid)
        )
        await asyncio.sleep(1)
        task.cancel()

        client_session_get_mock.assert_called()
        sleep_mock.sleep.assert_called_with(ONE_DAY_SLEEP)


@pytest.mark.parametrize(
    'cluster_config,update_check_config,registered_tasks',
    [
        ({'disabled': False, 'node_type': 'master'}, {UPDATE_CHECK_OSSEC_FIELD: 'yes'}, 2),
        ({'disabled': False, 'node_type': 'master'}, {UPDATE_CHECK_OSSEC_FIELD: 'no'}, 0),
        ({'disabled': False, 'node_type': 'worker'}, {UPDATE_CHECK_OSSEC_FIELD: 'yes'}, 0),
        ({'disabled': False, 'node_type': 'worker'}, {UPDATE_CHECK_OSSEC_FIELD: 'no'}, 0),
        ({'disabled': True, 'node_type': 'master'}, {UPDATE_CHECK_OSSEC_FIELD: 'yes'}, 2),
        ({'disabled': True, 'node_type': 'master'}, {UPDATE_CHECK_OSSEC_FIELD: 'no'}, 0),
        ({'disabled': True, 'node_type': 'worker'}, {UPDATE_CHECK_OSSEC_FIELD: 'yes'}, 2),
        ({'disabled': True, 'node_type': 'worker'}, {UPDATE_CHECK_OSSEC_FIELD: 'no'}, 0),
    ]
)
@patch('api.signals.check_installation_uid')
@patch('api.signals.get_update_information')
@patch('api.signals.get_ossec_conf')
@patch('api.signals.read_cluster_config')
@pytest.mark.asyncio
async def test_register_background_tasks(
    cluster_config_mock,
    ossec_conf_mock,
    get_update_information_mock,
    check_installation_uid_mock,
    cluster_config,
    update_check_config,
    registered_tasks
):
    class AwaitableMock(AsyncMock):
        def __await__(self):
            self.await_count += 1
            return iter([])

    cluster_config_mock.return_value = cluster_config
    ossec_conf_mock.return_value = update_check_config

    with patch('api.signals.asyncio') as create_task_mock:
        create_task_mock.create_task.return_value = AwaitableMock(spec=asyncio.Task)
        create_task_mock.create_task.return_value.cancel = AsyncMock()
        [_ async for _ in register_background_tasks({})]

        assert create_task_mock.create_task.call_count == registered_tasks
        assert create_task_mock.create_task.return_value.cancel.call_count == registered_tasks
