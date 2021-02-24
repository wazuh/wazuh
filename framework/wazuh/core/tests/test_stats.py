# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.exception import WazuhError, WazuhInternalError
        from wazuh.core import stats, common


@pytest.mark.parametrize("agent_id, daemon, response", [
    ('000', 'logcollector', '{"error":0, "data":{"test":0}}'),
    ('002', 'agent', '{"error":0, "data":{"test":0}}'),
    (3, 'test', '{"error":0, "data":{"test":0}}'),
])
def test_get_daemons_stats_from_socket(agent_id, daemon, response):
    """Check that get_daemons_stats_from_socket function uses the expected params and returns expected result.

    Parameters
    ----------
    agent_id : string
        Id of the agent to get stats from.
    daemon : string
        Name of the service to get stats from.
    response : string
        Response to be returned by the socket.
    """
    with patch('wazuh.core.stats.OssecSocket.__init__', return_value=None) as mock_socket:
        with patch('wazuh.core.stats.OssecSocket.send', side_effect=None) as mock_send:
            with patch('wazuh.core.stats.OssecSocket.receive', return_value=response.encode()):
                with patch('wazuh.core.stats.OssecSocket.close', side_effect=None):
                    result = stats.get_daemons_stats_from_socket(agent_id, daemon)

        if agent_id == '000':
            mock_socket.assert_called_once_with(os.path.join(common.ossec_path, "queue", "ossec", "logcollector"))
            mock_send.assert_called_once_with(b'getstate')
        else:
            mock_socket.assert_called_once_with(os.path.join(common.ossec_path, "queue", "ossec", "request"))
            mock_send.assert_called_once_with(f"{str(agent_id).zfill(3)} {daemon} getstate".encode())


def test_get_daemons_stats_from_socket_ko():
    """Check if get_daemons_stats_from_socket raises expected exceptions."""
    with pytest.raises(WazuhError, match=r'\b1307\b'):
        stats.get_daemons_stats_from_socket(None, None)

    with pytest.raises(WazuhError, match=r'\b1310\b'):
        stats.get_daemons_stats_from_socket('000', 'agent')

    with pytest.raises(WazuhInternalError, match=r'\b1121\b'):
        stats.get_daemons_stats_from_socket('000', 'logcollector')

    with patch('wazuh.core.stats.OssecSocket.__init__', return_value=None):
        with patch('wazuh.core.stats.OssecSocket.send', side_effect=None):
            with patch('wazuh.core.configuration.OssecSocket.receive', side_effect=ValueError):
                with pytest.raises(WazuhInternalError, match=r'\b1118\b'):
                    stats.get_daemons_stats_from_socket('000', 'logcollector')

            with patch('wazuh.core.configuration.OssecSocket.receive', return_value="err Error message test".encode()):
                with patch('wazuh.core.stats.OssecSocket.close', side_effect=None):
                    with pytest.raises(WazuhError, match=r'\b1117\b'):
                        stats.get_daemons_stats_from_socket('000', 'logcollector')
