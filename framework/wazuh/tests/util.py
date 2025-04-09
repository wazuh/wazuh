# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from functools import wraps

from wazuh.core.config.client import Config
from wazuh.core.config.models.indexer import IndexerConfig, IndexerNode
from wazuh.core.config.models.server import ServerConfig

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_default_configuration():
    """Get default configuration for the tests."""
    return Config(
        server=ServerConfig(),
        indexer=IndexerConfig(hosts=[IndexerNode(host='example', port=1516)], username='wazuh', password='wazuh'),
    )


def RBAC_bypasser(**kwargs_decorator):  # noqa: N802
    """Bypass RBAC `expose_resources` decorator."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return decorator
