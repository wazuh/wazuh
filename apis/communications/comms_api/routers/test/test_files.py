from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from wazuh.core.exception import WazuhCommsAPIError

from comms_api.core.files import DIR
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.files import get_files


class StatMock:
    """Auxiliary class."""

    def __init__(self):
        self.st_mode = 1
        self.st_size = 1
        self.st_mtime = 1


@pytest.mark.asyncio
@patch('os.stat', return_value=StatMock())
@pytest.mark.parametrize(
    'file_name,media_type',
    [
        ('test.txt', 'text/plain'),
        ('test.json', 'application/json'),
        ('test.so', 'application/octet-stream'),
        ('test.zip', 'application/zip'),
    ],
)
async def test_get_files(stat_mock, file_name, media_type):
    """Verify that the `get_files` handler works as expected."""
    response = await get_files(file_name)
    response_dict = response.__dict__

    assert response_dict['path'] == f'{DIR}/{file_name}'
    assert response_dict['status_code'] == status.HTTP_200_OK
    assert response_dict['filename'] == file_name
    assert response_dict['media_type'] == media_type


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'exception,message,code',
    [
        (WazuhCommsAPIError(2704), 'Invalid file name, it must not be a directory', 2704),
        (WazuhCommsAPIError(2705), 'Invalid file name, it must not contain directories', 2705),
        (FileNotFoundError(), 'File does not exist', status.HTTP_404_NOT_FOUND),
        (OSError('error'), 'error', status.HTTP_500_INTERNAL_SERVER_ERROR),
    ],
)
async def test_get_files_ko(exception, message, code):
    """Verify that the `get_files` handler catches exceptions successfully."""
    with patch('comms_api.routers.files.get_file_path', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=rf'{code}: {message}'):
            _ = await get_files('')
