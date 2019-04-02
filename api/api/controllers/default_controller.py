# # Copyright (C) 2015-2019, Wazuh Inc.
# # Created by Wazuh, Inc. <info@wazuh.com>.
# # This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import os
import socket
import time

import yaml

from api import __path__ as api_path

logger = logging.getLogger('wazuh')


def default_info():
    """Get basicinfo

    Returns various basic information about the API
    """
    stream = open(os.path.join(api_path[0], 'spec/spec.yaml'), 'r')
    info_data = yaml.load(stream)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime())
    data = {
        'title': info_data['info']['title'],
        'api_version': info_data['info']['version'],
        'revision': info_data['info']['x-revision'],
        'license_name': info_data['info']['license']['name'],
        'license_url': info_data['info']['license']['url'],
        'hostname': socket.gethostname(),
        'timestamp': timestamp
    }

    return data, 200
