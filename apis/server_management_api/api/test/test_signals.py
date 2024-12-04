import asyncio
import os
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from api.constants import INSTALLATION_UID_KEY, UPDATE_INFORMATION_KEY
from api.signals import (
    ONE_DAY_SLEEP,
    cancel_signal_handler,
    check_installation_uid,
    get_update_information,
    lifespan_handler,
    cti_context
)

# Fixtures
@pytest.fixture
def installation_uid_mock():
    with patch(
        'api.signals.INSTALLATION_UID_PATH', os.path.join('/tmp', INSTALLATION_UID_KEY)
    ) as path_mock:
        yield path_mock

        os.remove(path_mock)


@pytest.fixture
def query_update_check_service_mock():
    with patch('api.signals.query_update_check_service') as mock:
        yield mock


# Tests


@pytest.mark.asyncio
async def test_cancel_signal_handler_catch_cancelled_error_and_dont_rise():
    coroutine_mock = AsyncMock(side_effect=asyncio.CancelledError)
    await cancel_signal_handler(coroutine_mock)()

    coroutine_mock.assert_awaited_once()


@patch('api.signals.os.chmod')
@patch('api.signals.os.chown')
@patch('api.signals.common.wazuh_gid')
@patch('api.signals.common.wazuh_uid')
@pytest.mark.asyncio
async def test_check_installation_uid_populate_uid_if_not_exists(
    uid_mock, gid_mock, chown_mock, chmod_mock, installation_uid_mock
):
    uid = gid = 999
    uid_mock.return_value = uid
    gid_mock.return_value = gid

    await check_installation_uid()

    assert os.path.exists(installation_uid_mock)
    with open(installation_uid_mock) as file:
        assert cti_context[INSTALLATION_UID_KEY] == file.readline()
        chown_mock.assert_called_with(file.name, uid, gid)
        chmod_mock.assert_called_with(file.name, 0o660)


@pytest.mark.asyncio
async def test_check_installation_uid_get_uid_from_file(installation_uid_mock):
    installation_uid = str(uuid4())
    with open(installation_uid_mock, 'w') as file:
        file.write(installation_uid)

    await check_installation_uid()

    assert cti_context[INSTALLATION_UID_KEY] == installation_uid


@pytest.mark.asyncio
async def test_get_update_information_injects_correct_data_into_app_context(
    query_update_check_service_mock
):
    response_data = {
        'last_check_date': '2023-10-11T16:47:13.066946+00:00',
        'current_version': 'v4.8.0',
        'message': '',
        'status_code': 200,
        'last_available_major': {
            'tag': 'v5.0.0',
            'description': '',
            'title': 'Wazuh 5.0.0',
            'published_date': '2023-10-05T12:48:00Z',
            'semver': {'major': 5, 'minor': 0, 'patch': 0},
        },
        'last_available_minor': {
            'tag': 'v4.9.1',
            'description': '',
            'title': 'Wazuh 4.9.1',
            'published_date': '2023-10-05T12:47:00Z',
            'semver': {'major': 4, 'minor': 9, 'patch': 1},
        },
        'last_available_patch': {
            'tag': 'v4.8.2',
            'description': '',
            'title': 'Wazuh 4.8.2',
            'published_date': '2023-10-05T12:46:00Z',
            'semver': {'major': 4, 'minor': 8, 'patch': 2},
        },
    }

    query_update_check_service_mock.return_value = response_data
    cti_context[INSTALLATION_UID_KEY] = str(uuid4())
    task = asyncio.create_task(
        get_update_information()
    )
    await asyncio.sleep(1)
    task.cancel()

    query_update_check_service_mock.assert_called()

    assert cti_context[UPDATE_INFORMATION_KEY] == response_data


@pytest.mark.asyncio
async def test_get_update_information_schedule(query_update_check_service_mock):
    cti_context[INSTALLATION_UID_KEY] = str(uuid4())
    with patch('api.signals.asyncio') as sleep_mock:
        task = asyncio.create_task(
            get_update_information()
        )
        await asyncio.sleep(1)
        task.cancel()

        query_update_check_service_mock.assert_called()
        sleep_mock.sleep.assert_called_with(ONE_DAY_SLEEP)


@pytest.mark.parametrize(
    'cluster_config,update_check_config,registered_tasks',
    [
        (True, True, 2),
        (True, False, 1),
        (False, True, 0),
        (False, False, 0),
    ],
)
@patch('api.signals.check_installation_uid')
@patch('api.signals.get_update_information')
@patch('api.signals.update_check_is_enabled')
@patch('api.signals.running_in_master_node')
@pytest.mark.asyncio
async def test_register_background_tasks(
    running_in_master_node_mock,
    update_check_mock,
    get_update_information_mock,
    check_installation_uid_mock,
    cluster_config,
    update_check_config,
    registered_tasks,
):
    class AwaitableMock(AsyncMock):
        def __await__(self):
            self.await_count += 1
            return iter([])

    running_in_master_node_mock.return_value = cluster_config
    update_check_mock.return_value = update_check_config

    with patch('api.signals.asyncio') as create_task_mock:
        create_task_mock.create_task.return_value = AwaitableMock(spec=asyncio.Task)
        create_task_mock.create_task.return_value.cancel = AsyncMock()

        with TestClient(Starlette(lifespan=lifespan_handler)):
            assert create_task_mock.create_task.call_count == registered_tasks

        assert (
            create_task_mock.create_task.return_value.cancel.call_count
            == registered_tasks
        )
