# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import copy
import fcntl
import hashlib
import ipaddress
from base64 import b64encode
from datetime import date, datetime, timedelta, timezone
from glob import glob
from json import dumps, loads
from os import chown, chmod, path, makedirs, urandom, stat, remove
from platform import platform
from shutil import copyfile, rmtree
from time import time

from wazuh.core import common, configuration
from wazuh.core.InputValidator import InputValidator
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.database import Connection
from wazuh.core.exception import WazuhException, WazuhError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.ossec_queue import OssecQueue
from wazuh.core.utils import chmod_r, WazuhVersion, plain_dict_to_nested_dict, get_fields_to_nest, WazuhDBQuery, \
    WazuhDBQueryDistinct, WazuhDBQueryGroupBy, SQLiteBackend, WazuhDBBackend, safe_move
from wazuh.core.wazuh_socket import OssecSocket, OssecSocketJSON


def send_to_tasks_socket(command):
    """Send command task module

    Parameters
    ----------
    command : dict
        Command to be send to task module

    Returns
    -------
    Message received from the socket
    """
    s = OssecSocket(common.TASKS_SOCKET)
    s.send(dumps(command).encode())
    data = loads(s.receive().decode())
    s.close()

    return data
