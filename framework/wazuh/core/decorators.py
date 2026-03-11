# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from functools import wraps


def dapi_allower(func: callable):
    """Decorator to allow execution of a function through the distributed Wazuh API.

    Parameters
    ----------
    func : callable
        Function to be decorated.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    wrapper.__wazuh_exposed__ = True
    return wrapper
