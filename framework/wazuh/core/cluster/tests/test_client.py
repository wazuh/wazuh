import asyncio
import logging
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.common.getgrnam'):
    with patch('wazuh.common.getpwnam'):
        with patch('wazuh.common.ossec_uid'):
            with patch('wazuh.common.ossec_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core.cluster import client


logger = logging.getLogger('wazuh')
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

    result = await abstract_client_manager.start()
