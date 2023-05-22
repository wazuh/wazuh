# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from wazuh_testing.constants.paths import WAZUH_PATH


def delete_sockets(path=None):
    """Delete a list of Wazuh socket files or all of them if None is specified.

    Args:
        path (list, optional): Absolute socket path. Default `None`.
    """
    try:
        if path is None:
            path = os.path.join(WAZUH_PATH, 'queue', 'sockets')
            for file in os.listdir(path):
                os.remove(os.path.join(path, file))
            if os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb')):
                os.remove(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
            if os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock')):
                os.remove(os.path.join(WAZUH_PATH, 'queue',
                          'cluster', 'c-internal.sock'))
        else:
            for item in path:
                os.remove(item)
    except FileNotFoundError:
        pass
