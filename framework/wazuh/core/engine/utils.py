# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import WazuhError


def validate_response_or_raise(response: dict, error_code: int, resource_type: str):
    """Validate an engine response and raise an error if not OK.

    Parameters
    ----------
    response : dict
        The response dictionary from the engine.
    error_code : int
        The error code to use if raising an exception.
    resource_type: str
        The resource related to the exception.

    Raises
    ------
    WazuhError
        If the response status is not 'OK'.
    """
    if response['status'] != 'OK':
        extra_message =  {'cause': response['error'],
                          'resource_type': resource_type}
        raise WazuhError(error_code, extra_message=extra_message)
