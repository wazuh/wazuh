import asyncio
import logging
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.getgrnam'):
    with patch('wazuh.core.common.getpwnam'):
        with patch('wazuh.core.common.ossec_uid'):
            with patch('wazuh.core.common.ossec_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core.cluster import client

logger_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client.log')
logging.basicConfig(filename=logger_path, level=logging.INFO)
logger = logging.getLogger('client')

loop = asyncio.get_event_loop()


@pytest.mark.asyncio
async def test_AbstractClientManager():
    abstract_client_manager = client.AbstractClientManager(configuration={'node_name': 'master', 'nodes': ['master'],
                                                                          'port': 1111},
                                                           cluster_items={'node': 'master-node', 'intervals': {
                                                               'worker': {'connection_retry': 1}}},
                                                           enable_ssl=False, performance_test=False,
                                                           concurrency_test=False, file='None', string=20, logger=None)
    abstract_client = client.AbstractClient(loop=loop, on_con_lost=None, name='Testing',
                                            fernet_key='01234567891011121314151617181920',
                                            logger=logger, manager=abstract_client_manager,
                                            cluster_items={'node': 'master-node'})

    await abstract_client_manager.start()
    with open(logger_path, mode='r') as f:
        assert "ERROR:wazuh:Could not connect to master: [Errno -3] Temporary failure in name resolution. Trying again in 10 seconds." in f.read()

    os.remove(logger_path)
