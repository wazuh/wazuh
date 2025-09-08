# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.rbac.decorators import expose_resources
from wazuh.core.results import WazuhResult
from wazuh.core.exception import WazuhException
from wazuh.core.engine import get_engine_client, content, log

@expose_resources(actions=['content:status'], resources=['*:*:*'])
async def get_content_status() -> WazuhResult:
    """
    Get the status of all available content.

    Returns
    -------
    WazuhResult
        Result object with the operation outcome.
    """
    try:
        with get_engine_client() as client:
            module = content.ContentModule(client)
            response = await module.get_content_status()
            return WazuhResult(response)
    except WazuhException as e:
        if e.code == 2802:
            return WazuhResult({'message': 'Not Implemented'})
        raise e

@expose_resources(actions=['content:reload'], resources=['*:*:*'])
async def reload_contents() -> WazuhResult:
    """
    Reload all content files.

    Returns
    -------
    WazuhResult
        Result object with the operation outcome.
    """
    try:
        with get_engine_client() as client:
            module = content.ContentModule(client)
            response = await module.reload_content()
            return WazuhResult(response)
    except WazuhException as e:
        if e.code == 2802:
            return WazuhResult({'message': 'Not Implemented'})
        raise e

@expose_resources(actions=['decoders:validate'], resources=['*:*:*'])
async def validate_contents(type: str, payload: str) -> WazuhResult:
    """
    Validate a content file.

    Parameters
    ----------
    type : str
        The type of content to validate (e.g., "rule").
    payload : str
        The content file to validate.

    Returns
    -------
    WazuhResult
        Result object with the operation outcome.
    """
    try:
        with get_engine_client() as client:
            module = content.ContentModule(client)
            response = await module.validate_content(type, payload)
            return WazuhResult(response)
    except WazuhException as e:
        if e.code == 2802:
            return WazuhResult({'message': 'Not Implemented'})
        raise e

@expose_resources(actions=['decoders:validate'], resources=['*:*:*'])
async def log_tests(payload: str) -> WazuhResult:
    """
    Run log test for content files.

    Parameters
    ----------
    payload : str
        The log payload to test.

    Returns
    -------
    WazuhResult
        Result object with the operation outcome.
    """
    try:
        with get_engine_client() as client:
            module = log.LogModule(client)
            response = await module.log_test(payload)
            return WazuhResult(response)
    except WazuhException as e:
        if e.code == 2802:
            return WazuhResult({'message': 'Not Implemented'})
        raise e
