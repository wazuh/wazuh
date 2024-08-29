import os

from fastapi import status
from fastapi.responses import FileResponse

from comms_api.core.files import get_file_path
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import timeout
from wazuh.core.exception import WazuhCommsAPIError


@timeout(30)
async def get_files(file_name: str) -> FileResponse:
    """Get files endpoint handler.

    Parameters
    ----------
    file_name : str
        File name.

    Raises
    ------
    HTTPError
        If there is any system or validation error.

    Returns
    -------
    FileResponse
        File content response.
    """
    # TODO(#25121): implement files caching and security measures
    # See https://github.com/wazuh/wazuh/issues/24693#issuecomment-2278266040 for more information.
    try:
        path = get_file_path(file_name)
        stat_result = os.stat(path)
        return FileResponse(path, filename=file_name, stat_result=stat_result)
    except WazuhCommsAPIError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_400_BAD_REQUEST)
    except FileNotFoundError as exc:
        raise HTTPError(message='File does not exist', status_code=status.HTTP_404_NOT_FOUND)
    except OSError as exc:
        raise HTTPError(message=str(exc), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
