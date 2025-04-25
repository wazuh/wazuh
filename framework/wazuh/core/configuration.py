# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from os import path as os_path
from typing import Union

import wazuh.core.config.client
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.InputValidator import InputValidator
from wazuh.core.utils import get_group_file_path, load_wazuh_yaml, validate_wazuh_configuration

logger = logging.getLogger('wazuh')

# Aux functions

# Type of configuration sections:
#   * Duplicate -> there can be multiple independent sections. Must be returned as multiple json entries.
#   * Merge -> there can be multiple sections but all are dependent with each other. Must be returned as a single json
#   entry.
#   * Last -> there can be multiple sections in the configuration but only the last one will be returned.
#   The rest are ignored.
GETCONFIG_COMMAND = 'getconfig'
UPDATE_CHECK_OSSEC_FIELD = 'update_check'
GLOBAL_KEY = 'global'
YES_VALUE = 'yes'
CTI_URL_FIELD = 'cti-url'
DEFAULT_CTI_URL = 'https://cti.wazuh.com'


def get_group_conf(group_id: str = None, raw: bool = False) -> Union[dict, str]:
    """Return group configuration as dictionary.

    Parameters
    ----------
    group_id : str
        ID of the group with the configuration we want to get.
    raw : bool
        Respond in raw format.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1006)
        group configuration does not exist or there is a problem with the permissions.

    Returns
    -------
    dict or str
        Group configuration as dictionary.
    """
    filepath = get_group_file_path(group_id)
    if not os_path.exists(filepath):
        raise WazuhResourceNotFound(1710, group_id)

    if raw:
        try:
            # Read RAW file
            with open(filepath, 'r') as raw_data:
                data = raw_data.read()
                return data
        except Exception as e:
            raise WazuhError(1006, str(e))

    # Parse YAML
    data = load_wazuh_yaml(filepath)

    return {'total_affected_items': len(data), 'affected_items': data}


def update_group_configuration(group_id: str, file_content: str) -> str:
    """Update group configuration.

    Parameters
    ----------
    group_id : str
        Group to update.
    file_content : str
        File content of the new configuration in a string.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhInternalError(1006)
        Error writing file.

    Returns
    -------
    str
        Confirmation message.
    """
    filepath = get_group_file_path(group_id)

    if not os_path.exists(filepath):
        raise WazuhResourceNotFound(1710, group_id)

    validate_wazuh_configuration(file_content)

    try:
        with open(filepath, 'w') as f:
            f.write(file_content)
    except Exception as e:
        raise WazuhError(1006, extra_message=str(e))

    return 'Agent configuration was successfully updated'


def update_group_file(group_id: str, file_data: str) -> str:
    """Update a group file.

    Parameters
    ----------
    group_id : str
        Group to update.
    file_data : str
        Upload data.

    Raises
    ------
    WazuhError(1722)
        If there was a validation error.
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1112)
        Empty files are not supported.

    Returns
    -------
    str
        Confirmation message in string.
    """
    if not InputValidator().group(group_id):
        raise WazuhError(1722)

    if not os_path.exists(get_group_file_path(group_id)):
        raise WazuhResourceNotFound(1710, group_id)

    if len(file_data) == 0:
        raise WazuhError(1112)

    return update_group_configuration(group_id, file_data)


def update_check_is_enabled() -> bool:
    """Read the ossec.conf and check UPDATE_CHECK_OSSEC_FIELD value.

    Returns
    -------
    bool
        True if UPDATE_CHECK_OSSEC_FIELD is 'yes' or isn't present, else False.
    """
    try:
        config_value = wazuh.core.config.client.CentralizedConfig.get_server_config().cti.update_check
        return config_value
    except WazuhError as e:
        if e.code != 1106:
            raise e
        return True


def get_cti_url() -> str:
    """Get the CTI service URL from the configuration.

    Returns
    -------
    str
        CTI service URL. The default value is returned if CTI_URL_FIELD isn't present.
    """
    try:
        return wazuh.core.config.client.CentralizedConfig.get_server_config().cti.url
    except WazuhError as e:
        if e.code != 1106:
            raise e
        return DEFAULT_CTI_URL
