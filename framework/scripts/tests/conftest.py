# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch

from wazuh.core.config.client import Config
from wazuh.core.config.models.indexer import IndexerConfig, IndexerSSLConfig
from wazuh.core.config.models.server import ServerConfig


def get_default_configuration():
    """Get default configuration for the tests."""
    with patch('wazuh.core.config.models.indexer.KeystoreReader.__new__') as keystore_mock:
        keystore_mock.return_value = MagicMock()

        return Config(
            server=ServerConfig(),
            indexer=IndexerConfig(hosts=['http://example:9200'], ssl=IndexerSSLConfig()),
        )
