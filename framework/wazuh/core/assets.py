# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import tempfile

from os import chmod, path
from shutil import Error

from wazuh import WazuhError, WazuhInternalError
from wazuh.core import common, utils, results
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType


DEFAULT_PERMISSIONS = 0o660

def generate_asset_filename(filename: str) -> str:
    """Generate a safe asset filename from a given string.

    Parameters
    ----------
    filename : str
        The original filename.

    Returns
    -------
    str
        The sanitized filename.
    """
    return filename.strip('/').replace('/', '_').replace(' ', '_')

def generate_asset_file_path(filename: str, policy_type: PolicyType, resource_type: ResourceType) -> str:
    """Generate the full file path for an asset based on its policy type.

    Parameters
    ----------
    filename : str
        The asset filename.
    policy_type : PolicyType
        The policy type for the asset.
    resource_type : ResourceType
        The policy type for the asset.

    Returns
    -------
    str
        The full file path for the asset.
    """
    if resource_type == ResourceType.KVDB:
        base_path = path.join(common.USER_KVDB_BASE_PATH, policy_type.dirname())
    else:
        base_path = path.join(common.USER_ASSETS_PATH, policy_type.dirname(), resource_type.dirname())
    safe_filename = generate_asset_filename(filename)
    if not safe_filename.endswith('.json'):
        safe_filename += '.json'

    return path.join(base_path, safe_filename)


def save_asset_file(file_path: str, content: str, permissions = DEFAULT_PERMISSIONS) -> results.WazuhResult:
    """Save asset content to a file, handling permissions and atomic move.

    Parameters
    ----------
    file_path : str
        The destination file path.
    content : str
        The content to write.
    permissions : int, optional
        The file permissions to set (default is 0o660).

    Returns
    -------
    WazuhResult
        Result object indicating success or failure.
    """
    handle, tmp_file_path = tempfile.mkstemp(prefix='api_tmp_file_', suffix='.tmp', dir=common.OSSEC_TMP_PATH)

    # Creates temporary file
    try:
        with open(handle, 'w') as tmp_file:
            tmp_file.write(content)
        chmod(tmp_file_path, permissions)
    except IOError as exc:
        raise WazuhInternalError(1005) from exc

    # Move temporary file to group folder
    try:
        utils.safe_move(tmp_file_path, file_path, ownership=(common.wazuh_uid(), common.wazuh_gid()), permissions=permissions)
    except PermissionError as exc:
        raise WazuhError(1006) from exc
    except Error as exc:
        raise WazuhInternalError(1016) from exc

    return results.WazuhResult({'message': 'File was successfully updated'})
