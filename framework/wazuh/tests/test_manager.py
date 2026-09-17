#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import operator
import os
import socket
import sys
from unittest.mock import patch, MagicMock, mock_open

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.manager import *
        from wazuh.core.manager import LoggingFormat
        from wazuh.core.tests.test_manager import get_logs
        from wazuh import WazuhInternalError, WazuhError
        from wazuh.core.engine_http import RemotedAdminHTTPError

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture(scope='module', autouse=True)
def mock_wazuh_path():
    with patch('wazuh.core.common.WAZUH_PATH', new=test_data_path):
        yield


@pytest.fixture(scope='module', autouse=True)
def installed_schema():
    """The schema the installer copies to etc/wazuh-manager.schema.json, from its source in the repository."""
    schema_path = os.path.join(test_data_path, '..', '..', '..', '..', 'src', 'shared_modules', 'manager_config', 'schema',
                               'wazuh-manager.schema.json')
    with patch('wazuh.core.common.MANAGER_CONF_SCHEMA', new=schema_path):
        yield


class InitManager:
    def __init__(self):
        """Sets up necessary environment to test manager functions"""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')


@pytest.fixture(scope='module')
def test_manager():
    # Set up
    test_manager = InitManager()
    return test_manager


manager_status = {'wazuh-manager-analysisd': 'running', 'wazuh-manager-authd': 'running',
 'wazuh-manager-remoted': 'running',
 'wazuh-manager-clusterd': 'running', 'wazuh-manager-modulesd': 'running',
 'wazuh-manager-db': 'running', 'wazuh-manager-apid': 'running'}

ENGINE_STATUS_READY = {
    'ready': True,
    'spaces': {'standard': {'available': True, 'enabled': True, 'status': 'ready', 'hash': 'h',
                            'last_successful_update': 1}},
    'ioc': {'connection': {'available': True, 'status': 'ready', 'hash': 'h', 'last_successful_update': 1}},
    'geo': {'city': {'available': True, 'status': 'ready', 'hash': 'h', 'last_successful_update': 1}},
}

VD_STATUS_READY = {
    'available': True,
    'status': 'ready',
    'enabled': True,
    'offset': 42,
    'last_successful_update': 1719878400,
}

REMOTED_STATUS_READY = {
    'ready': True,
    'keystore': {'readable': True, 'agents_loaded': 5, 'entries_skipped': 0},
    'enrollment_password': {'ready': True},
}

WDB_STATUS_READY = {'status': 'ok', 'module': 'wazuh-db', 'global': {'available': True}}

WDB_STATUS_UNAVAILABLE = {'status': 'unavailable', 'module': 'wazuh-db',
                          'global': {'available': False, 'missing_tables': ['belongs', 'group']}}


def _make_modulesd_mock(vd_status=None, side_effect=None):
    """Return a (mock_cls, mock_instance) pair for VdHTTPClient."""
    mock_cls = MagicMock()
    mock_instance = MagicMock()
    if side_effect is not None:
        mock_instance.get_status.side_effect = side_effect
    else:
        mock_instance.get_status.return_value = vd_status or VD_STATUS_READY
    mock_cls.return_value = mock_instance
    return mock_cls, mock_instance


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_wdb_running_but_unable_is_not_ready(mock_status, mock_engine_cls, mock_modulesd_cls,
                                                        mock_remoted_cls, mock_wdb_cls):
    """A running wazuh-db that cannot serve must make the node unready.

    This is the state a PID check cannot see and the one issue #39429 reports: the process is up,
    its socket answers, and it still cannot query global.db -- so remoted's POST /control fails for
    every agent while events keep flowing.
    """
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_UNAVAILABLE})

    data = get_status().affected_items[0]

    assert data['wazuh-manager-db']['running'] is True, 'the process is up: that is the whole point'
    assert data['wazuh-manager-db']['ready'] is False
    assert data['wazuh-manager-db']['global']['missing_tables'] == ['belongs', 'group'], \
        'the entry must carry WHAT is wrong, not just that something is'
    assert data['ready'] is False, 'one unready daemon makes the node unready'


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_wdb_socket_unreachable_is_not_ready(mock_status, mock_engine_cls, mock_modulesd_cls,
                                                        mock_remoted_cls, mock_wdb_cls):
    """An unreachable wazuh-db socket is a real unready state, not an optional side channel.

    Unlike remoted's admin plane -- which can fail to come up independently of the daemon, and so
    falls back to plain liveness -- this socket is the same daemon answering. Being unable to reach
    it while the process runs means it cannot serve.
    """
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})
    mock_wdb_cls.return_value = MagicMock(**{'get_status.side_effect': WazuhInternalError(2036)})

    data = get_status().affected_items[0]

    assert data['wazuh-manager-db']['ready'] is False
    assert 'reason' in data['wazuh-manager-db'], 'the operator needs to know it was unreachable'
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_all_ready(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """Node ready: all daemons running, analysisd engine ready, modulesd VD ready, remoted keystore/password ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine = MagicMock()
    mock_engine.get_status.return_value = ENGINE_STATUS_READY
    mock_engine_cls.return_value = mock_engine
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    result = get_status()
    assert isinstance(result, AffectedItemsWazuhResult)
    data = result.affected_items[0]

    assert data['ready'] is True
    # analysisd embeds the engine resources
    assert data['wazuh-manager-analysisd']['running'] is True
    assert data['wazuh-manager-analysisd']['ready'] is True
    assert 'spaces' in data['wazuh-manager-analysisd']
    assert 'ioc' in data['wazuh-manager-analysisd']
    assert 'geo' in data['wazuh-manager-analysisd']
    # modulesd embeds all manager-exclusive modules under 'modules' key
    assert data['wazuh-manager-modulesd']['ready'] is True
    modules = data['wazuh-manager-modulesd']['modules']
    assert modules['vulnerability-detector'] == VD_STATUS_READY
    assert modules['inventory-sync'] == {'available': True}
    assert modules['content-manager'] == {'available': True}
    assert modules['task-manager'] == {'available': True}
    # remoted embeds keystore/enrollment_password readiness from its admin GET /status
    assert data['wazuh-manager-remoted']['running'] is True
    assert data['wazuh-manager-remoted']['ready'] is True
    assert data['wazuh-manager-remoted']['keystore'] == REMOTED_STATUS_READY['keystore']
    assert data['wazuh-manager-remoted']['enrollment_password'] == REMOTED_STATUS_READY['enrollment_password']


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_analysisd_not_ready(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """analysisd engine not ready → node not ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine = MagicMock()
    mock_engine.get_status.return_value = {'ready': False, 'spaces': {}, 'ioc': {}, 'geo': {}}
    mock_engine_cls.return_value = mock_engine
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-analysisd']['ready'] is False
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_engine_unreachable(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """Engine unreachable → analysisd not ready → node not ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    from wazuh.core.exception import WazuhInternalError
    mock_engine = MagicMock()
    mock_engine.get_status.side_effect = WazuhInternalError(2021)
    mock_engine_cls.return_value = mock_engine
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-analysisd']['ready'] is False
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value={**manager_status, 'wazuh-manager-analysisd': 'stopped'})
def test_get_status_analysisd_stopped(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """analysisd stopped → not running, not ready, engine not queried."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-analysisd']['running'] is False
    assert data['wazuh-manager-analysisd']['ready'] is False
    assert data['ready'] is False
    mock_engine_cls.assert_not_called()


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_modulesd_updating(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """A background VD update keeps the previous feed available but the node is not ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{
        'get_status.return_value': {**VD_STATUS_READY, 'status': 'updating'},
    })
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-modulesd']['ready'] is False
    assert data['wazuh-manager-modulesd']['modules']['vulnerability-detector']['available'] is True
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_modulesd_unreachable(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """modulesd socket unreachable → modulesd not ready → node not ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    from wazuh.core.exception import WazuhInternalError
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.side_effect': WazuhInternalError(2026)})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-modulesd']['ready'] is False
    modules = data['wazuh-manager-modulesd']['modules']
    assert modules['vulnerability-detector'] == {'available': False, 'status': 'failed'}
    assert modules['inventory-sync'] == {'available': True}
    assert modules['content-manager'] == {'available': True}
    assert modules['task-manager'] == {'available': True}
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value={**manager_status, 'wazuh-manager-modulesd': 'stopped'})
def test_get_status_modulesd_stopped(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """modulesd stopped → not running, not ready, socket not queried."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-modulesd']['running'] is False
    assert data['wazuh-manager-modulesd']['ready'] is False
    assert data['ready'] is False
    mock_modulesd_cls.assert_not_called()


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_modulesd_vd_disabled(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """VD disabled → modulesd ready (disabled VD is not a readiness blocker)."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{
        'get_status.return_value': {
            'available': False, 'status': 'updating', 'enabled': False, 'offset': 0,
            'last_successful_update': 0,
        },
    })
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-modulesd']['ready'] is True
    assert data['ready'] is True


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_modulesd_vd_failed(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """VD feed error → modulesd not ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{
        'get_status.return_value': {
            'available': True, 'status': 'failed', 'enabled': True, 'offset': 0,
            'last_successful_update': 0,
        },
    })
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-modulesd']['ready'] is False
    assert data['wazuh-manager-modulesd']['modules']['vulnerability-detector']['available'] is True
    assert data['wazuh-manager-modulesd']['modules']['vulnerability-detector']['status'] == 'failed'
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_remoted_ready(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """remoted running, keystore and enrollment password both ready → remoted (and node) ready."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': REMOTED_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted']['ready'] is True
    assert data['wazuh-manager-remoted']['keystore'] == REMOTED_STATUS_READY['keystore']
    assert data['wazuh-manager-remoted']['enrollment_password'] == REMOTED_STATUS_READY['enrollment_password']
    assert data['ready'] is True


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_remoted_keystore_failure_does_not_gate_ready(
    mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls
, mock_wdb_cls):
    """client.keys' last reload failed but Password-mode is disabled → keystore never gates `ready`."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': {
        'ready': True,
        'keystore': {'readable': False, 'agents_loaded': 5, 'entries_skipped': 0},
    }})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted']['ready'] is True
    assert data['wazuh-manager-remoted']['keystore']['readable'] is False
    assert 'enrollment_password' not in data['wazuh-manager-remoted']
    assert data['ready'] is True


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_remoted_password_unavailable_not_ready(
    mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls
, mock_wdb_cls):
    """Password-mode enabled, key unavailable → not ready regardless of `keystore.readable`."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': {
        'ready': False,
        'keystore': {'readable': True, 'agents_loaded': 5, 'entries_skipped': 0},
        'enrollment_password': {'ready': False},
    }})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted']['ready'] is False
    assert data['wazuh-manager-remoted']['enrollment_password']['ready'] is False
    assert data['ready'] is False


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_remoted_password_mode_disabled(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """Password-mode enrollment disabled → `enrollment_password` is absent from the entry, not a not-applicable state."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.return_value': {
        'ready': True,
        'keystore': {'readable': True, 'agents_loaded': 5, 'entries_skipped': 0},
    }})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted']['ready'] is True
    assert 'enrollment_password' not in data['wazuh-manager-remoted']
    assert data['ready'] is True


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_remoted_admin_socket_unreachable(
    mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls
, mock_wdb_cls):
    """Admin socket unreachable (ConnectError, code 2031) → falls back to plain liveness, reason surfaced."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.side_effect': WazuhInternalError(2031)})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted'] == {
        'ready': True, 'running': True, 'reason': 'admin socket unreachable',
    }
    assert data['ready'] is True


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_status_remoted_timeout_still_not_ready(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """A request timeout (code 2030, not a ConnectError) keeps today's `ready: false` -- the admin-socket-
    unreachable fallback is scoped to code 2031 only, not any `RemotedHTTPClient` failure."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})
    mock_remoted_cls.return_value = MagicMock(**{'get_status.side_effect': WazuhInternalError(2030)})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted']['running'] is True
    assert data['wazuh-manager-remoted']['ready'] is False
    assert 'reason' not in data['wazuh-manager-remoted']
    assert data['ready'] is False


REMOTED_TLS_DOCUMENT = {
    'evaluated_at': '2026-09-15T10:00:00Z', 'evaluated_at_ts': 1789466400,
    'listener': {
        'subject': 'CN=manager-01', 'issuer': 'CN=Corp Root CA', 'sans': ['manager-01.example.com', '10.0.0.5'],
        'not_before': '2026-01-01T00:00:00Z', 'not_before_ts': 1767225600,
        'not_after': '2027-01-01T00:00:00Z', 'not_after_ts': 1798761600,
        'seconds_until_expiry': 9295200, 'fingerprint': 'x509-sha256:' + 'a' * 64, 'serial': '0x01',
        'path': 'etc/certs/remoted.pem', 'loaded_at': '2026-09-14T08:12:31Z', 'loaded_at_ts': 1789373551,
    },
    'ca_bundle': {
        'path': 'etc/certs/root-ca.pem', 'publication': 0, 'publication_vouched': False,
        'content_sha256': 'b' * 64, 'certificates_count': 1, 'certificates_limit': 6,
        'serialized_bytes': 1200, 'serialized_bytes_limit': 8191, 'chain_valid': True,
        'certificates': [{'subject': 'CN=Corp Root CA', 'fingerprint': 'x509-sha256:' + 'c' * 64,
                          'signs_active_leaf': True}],
    },
}


@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_remoted_tls_returns_the_document_with_the_node(mock_status, mock_remoted_cls):
    """remoted answered: one affected item, `node` added by the framework, `available: true`, the
    document passed through untouched."""
    mock_remoted_cls.return_value = MagicMock(**{'get_tls.return_value': REMOTED_TLS_DOCUMENT})

    result = get_remoted_tls()
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.failed_items == {}
    item = result.affected_items[0]
    assert item['node'] == node_id
    assert item['available'] is True
    assert item['listener'] == REMOTED_TLS_DOCUMENT['listener']
    assert item['ca_bundle'] == REMOTED_TLS_DOCUMENT['ca_bundle']
    assert item['evaluated_at_ts'] == 1789466400
    assert 'was returned' in result.message
    mock_remoted_cls.return_value.close.assert_called_once()


@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_remoted_tls_passes_negative_expiry_through(mock_status, mock_remoted_cls):
    """An expired certificate reads negative seconds; the framework applies no threshold and
    changes no value."""
    expired = {**REMOTED_TLS_DOCUMENT, 'listener': {**REMOTED_TLS_DOCUMENT['listener'], 'seconds_until_expiry': -86400}}
    mock_remoted_cls.return_value = MagicMock(**{'get_tls.return_value': expired})

    item = get_remoted_tls().affected_items[0]
    assert item['listener']['seconds_until_expiry'] == -86400
    assert 'warning' not in item and 'critical' not in item


@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.status', return_value={**manager_status, 'wazuh-manager-remoted': 'stopped'})
def test_get_remoted_tls_remoted_not_running(mock_status, mock_remoted_cls):
    """remoted down: an explicit unavailable item, still with `node`, and the admin socket never queried."""
    result = get_remoted_tls()
    assert result.total_affected_items == 1
    assert result.failed_items == {}
    assert result.affected_items[0] == {'node': node_id, 'available': False, 'reason': 'remoted not running'}
    mock_remoted_cls.assert_not_called()


@pytest.mark.parametrize('side_effect, reason', [
    (WazuhInternalError(2031), 'admin socket unreachable'),
    (WazuhInternalError(2030), 'timeout'),
    (WazuhInternalError(2032), 'invalid response'),
    (WazuhInternalError(2028), 'admin client unavailable'),
    (RemotedAdminHTTPError(503, extra_message='{"error":"Service unavailable","code":503}'), 'listener not started'),
    (RemotedAdminHTTPError(500, extra_message='{"error":"Internal server error","code":500}'), 'unexpected response'),
    (WazuhError(2029), 'unexpected response'),
    (WazuhError(2013), 'request failed'),
])
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.status', return_value=manager_status)
def test_get_remoted_tls_degrades_to_an_unavailable_item(mock_status, mock_remoted_cls, side_effect, reason):
    """Every failure that is remoted's own state becomes `{node, available: false, reason}` -- never a
    failed item, never an exception, never an empty certificate list."""
    mock_remoted_cls.return_value = MagicMock(**{'get_tls.side_effect': side_effect})

    result = get_remoted_tls()
    assert result.total_affected_items == 1
    assert result.failed_items == {}
    assert result.affected_items[0] == {'node': node_id, 'available': False, 'reason': reason}
    mock_remoted_cls.return_value.close.assert_called_once()


@patch('wazuh.manager.WazuhDBStatusHTTPClient')
@patch('wazuh.manager.RemotedHTTPClient')
@patch('wazuh.manager.VdHTTPClient')
@patch('wazuh.manager.EngineHTTPClient')
@patch('wazuh.manager.status', return_value={**manager_status, 'wazuh-manager-remoted': 'stopped'})
def test_get_status_remoted_stopped(mock_status, mock_engine_cls, mock_modulesd_cls, mock_remoted_cls, mock_wdb_cls):
    """remoted stopped → not running, not ready, admin socket never queried."""
    mock_wdb_cls.return_value = MagicMock(**{'get_status.return_value': WDB_STATUS_READY})
    mock_engine_cls.return_value = MagicMock(**{'get_status.return_value': ENGINE_STATUS_READY})
    mock_modulesd_cls.return_value = MagicMock(**{'get_status.return_value': VD_STATUS_READY})

    data = get_status().affected_items[0]
    assert data['wazuh-manager-remoted']['running'] is False
    assert data['wazuh-manager-remoted']['ready'] is False
    assert data['ready'] is False
    mock_remoted_cls.assert_not_called()


@pytest.mark.parametrize('tag, level, total_items, sort_by, sort_ascending', [
    (None, None, 7, None, None),
    ('wazuh-manager-modulesd:database', None, 2, None, None),
    ('wazuh-manager-modulesd:aws-s3', None, 5, None, None),
    ('random', None, 0, ['timestamp'], True),
    (None, 'info', 2, ['timestamp'], False),
    (None, 'error', 1, ['level'], True),
    (None, 'debug', 2, ['level'], False),
    (None, None, 7, ['tag'], True),
    (None, 'random', 0, None, True),
    (None, 'warning', 2, None, False)
])
@patch("wazuh.core.manager.get_wazuh_active_logging_format", return_value=LoggingFormat.plain)
@patch("wazuh.core.manager.exists", return_value=True)
def test_ossec_log(mock_exists, mock_active_logging_format, tag, level, total_items, sort_by, sort_ascending):
    """Test reading wazuh-manager.log file contents.

    Parameters
    ----------
    level : str
        Filters by log type: all, error or info.
    tag : str
        Filters by log category (i.e. wazuh-manager-remoted).
    total_items : int
        Expected items to be returned after calling ossec_log.
    sort_by : list
        Fields to sort the items by.
    sort_ascending : boolean
        Sort in ascending (true) or descending (false) order.
    """
    with patch('wazuh.core.manager.tail') as tail_patch:
        # Return ossec_log_file when calling tail() method
        ossec_log_file = get_logs()
        tail_patch.return_value = ossec_log_file.splitlines()

        result = ossec_log(level=level, tag=tag, sort_by=sort_by, sort_ascending=sort_ascending)

        # Assert type, number of items and presence of trailing characters
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_affected_items'] == total_items
        assert all(log['description'][-1] != '\n' for log in result.render()['data']['affected_items'])
        if tag is not None:
            assert all('\n' not in log['description'] for log in result.render()['data']['affected_items'])
        if sort_by:
            reversed_result = ossec_log(level=level, tag=tag, sort_by=sort_by, sort_ascending=not sort_ascending)
            for i in range(total_items):
                assert result.render()['data']['affected_items'][i][sort_by[0]] == \
                       reversed_result.render()['data']['affected_items'][total_items - 1 - i][sort_by[0]]


@pytest.mark.parametrize('q, field, operation, values', [
    ('level=debug,level=error', 'level', 'OR', 'debug, error'),
    ('timestamp=2019/03/26 19:49:15', 'timestamp', '=', '2019/03/26T19:49:15Z'),
    ('timestamp<2019/03/26 19:49:14', 'timestamp', '<', '2019/03/26T19:49:15Z'),
])
@patch("wazuh.core.manager.get_wazuh_active_logging_format", return_value=LoggingFormat.plain)
@patch("wazuh.core.manager.exists", return_value=True)
def test_ossec_log_q(mock_exists, mock_active_logging_format, q, field, operation, values):
    """Check that the 'q' parameter is working correctly.

    Parameters
    ----------
    q : str
        Query to execute.
    field : str
        Field affected by the query.
    operation : str
        Operation type to be performed in the query.
    values : str
        Values used for the comparison.
    """
    with patch('wazuh.core.manager.tail') as tail_patch:
        ossec_log_file = get_logs()
        tail_patch.return_value = ossec_log_file.splitlines()

        result = ossec_log(q=q)

        if operation != 'OR':
            operators = {'=': operator.eq, '!=': operator.ne, '<': operator.lt, '>': operator.gt}
            assert all(operators[operation](log[field], values) for log in result.render()['data']['affected_items'])
        else:
            assert all(log[field] in values for log in result.render()['data']['affected_items'])


@patch("wazuh.core.manager.get_wazuh_active_logging_format", return_value=LoggingFormat.plain)
@patch("wazuh.core.manager.exists", return_value=True)
def test_ossec_log_summary(mock_exists, mock_active_logging_format):
    """Tests ossec_log_summary function works and returned data match with expected"""
    expected_result = {
        'wazuh-manager-modulesd:aws-s3': {'all': 5, 'info': 2, 'error': 1, 'critical': 0, 'warning': 2, 'debug': 0},
        'wazuh-manager-modulesd:database': {'all': 2, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 2}
    }

    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = ossec_log_summary()

        # Assert data match what was expected and type of the result.
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_affected_items'] == len(expected_result.keys())
        assert all(all(value == expected_result[key] for key, value in item.items())
                   for item in result.render()['data']['affected_items'])


def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_config().render()

    assert 'node_api_config' in result['data']['affected_items'][0]
    assert result['data']['affected_items'][0]['node_name'] == 'node01'


@patch('socket.socket')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('wazuh.core.cluster.utils.open')
@patch('os.path.exists', return_value=True)
def test_restart_ok(mock_exists, mock_path, mock_fcntl, mock_socket):
    """Tests restarting a manager"""
    result = restart()

    # Assert there are no errors and type of the result.
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


@patch('wazuh.core.cluster.utils.open')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('os.path.exists', return_value=False)
def test_restart_ko_socket(mock_exists, mock_fcntl, mock_open):
    """Tests restarting a manager exceptions"""

    # Socket path not exists
    with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
        restart()

    # Socket error
    with patch("os.path.exists", return_value=True):
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1902 .*'):
                restart()

        with patch('socket.socket.connect'):
            with patch('socket.socket.send', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                    restart()


@patch('socket.socket')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('wazuh.core.cluster.utils.open')
@patch('os.path.exists', return_value=True)
def test_reload_ok(mock_exists, mock_path, mock_fcntl, mock_socket):
    """Tests reloading a manager."""
    result = reload()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


@patch('wazuh.core.cluster.utils.open')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('os.path.exists', return_value=False)
def test_reload_ko_socket(mock_exists, mock_fcntl, mock_open):
    """Tests reload() exceptions related to socket errors.

    Unlike restart(), reload() catches WazuhInternalError internally, so socket
    errors are surfaced as failed_items rather than raised exceptions.
    """
    # Socket path not exists -> WazuhInternalError(1901) caught, added to failed_items
    result = reload()
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.render()['data']['total_failed_items'] == 1
    assert result.render()['data']['total_affected_items'] == 0

    # Socket connection error -> WazuhInternalError(1902) caught, added to failed_items
    with patch('os.path.exists', return_value=True):
        with patch('socket.socket', side_effect=socket.error):
            result = reload()
            assert result.render()['data']['total_failed_items'] == 1
            assert result.render()['data']['total_affected_items'] == 0

        # Send error -> WazuhInternalError(1014) caught, added to failed_items
        with patch('socket.socket.connect'):
            with patch('socket.socket.send', side_effect=socket.error):
                result = reload()
                assert result.render()['data']['total_failed_items'] == 1
                assert result.render()['data']['total_affected_items'] == 0


@pytest.mark.parametrize('error_flag, error_msg', [
    (0, ""),
    (1, "2019/02/27 11:30:07 wazuh-manager-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: "
        "Unspecified key"),
    (1, "2019/02/27 11:30:24 wazuh-manager-authd: ERROR: (1230): Invalid element in the configuration: "
        "'use_source_i'.\n2019/02/27 11:30:24 wazuh-manager-authd: ERROR: (1202): Configuration error at "
        "'/var/wazuh-manage/etc/wazuh-manager.conf'.")
])
@patch('wazuh.manager.validate_manager_conf')
def test_validation(mock_validate_manager_conf, error_flag, error_msg):
    """Test validation() method works as expected

    Tests configuration validation function with multiple scenarios:
        * No errors found in configuration
        * Error found in cluster configuration
        * Error found in any other configuration

    Parameters
    ----------
    error_flag : int
        Error flag (0 = success, 1 = error).
    error_msg : str
        Error message if validation fails.
    """
    if error_flag == 0:
        # Success case - validation passes
        mock_validate_manager_conf.return_value = {'status': 'OK'}
    else:
        # Error case - validation fails
        mock_validate_manager_conf.side_effect = WazuhError(1908, extra_message=error_msg)

    result = validation()

    # Assert if error was returned
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == error_flag


@pytest.mark.parametrize('exception', [
    WazuhInternalError(1020),  # File not found
    WazuhError(1113),  # XML validation error
    WazuhError(1908)  # General validation error
])
@patch('wazuh.manager.validate_manager_conf')
def test_validation_ko(mock_validate, exception):
    mock_validate.side_effect = exception

    if isinstance(exception, WazuhInternalError):
        with pytest.raises(WazuhInternalError, match='.* 1020 .*'):
            validation()
    else:
        result = validation()
        assert not result.affected_items
        assert result.total_failed_items == 1


@patch('wazuh.core.configuration.get_active_configuration')
def test_get_config(mock_act_conf):
    """Tests get_config() method works as expected"""
    get_config('component', 'config')

    # Assert whether get_active_configuration() method receives the expected parameters.
    mock_act_conf.assert_called_once_with(component='component', configuration='config')


def test_get_config_ko():
    """Tests get_config() function returns an error"""
    result = get_config()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1307


_EFFECTIVE_STUB = {'cluster': {'name': 'wazuh', 'node_name': 'master-node', 'node_type': 'master',
                               'key': '9d273b53510fef702b54a92e9cffc82e'},
                   'logging': {'log_format': ['plain']}}


@pytest.mark.parametrize('raw', [True, False])
@patch('wazuh.core.configuration.load_manager_conf', return_value=_EFFECTIVE_STUB)
def test_read_manager_conf(load_mock, raw):
    """Tests read_manager_conf() function works as expected"""
    result = read_manager_conf(raw=raw)

    if raw:
        assert isinstance(result, str), 'No expected result type'
    else:
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_failed_items'] == 0


@patch('wazuh.core.configuration.load_manager_conf', return_value=_EFFECTIVE_STUB)
def test_read_manager_conf_ko(load_mock):
    """Tests read_manager_conf() function returns an error"""
    result = read_manager_conf(section='test')

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1102


# ---------------------------------------------------------------------------
# Tests for cluster.key masking in read_manager_conf (CVE fix)
# ---------------------------------------------------------------------------

_MANAGER_CONF_WITH_CLUSTER_KEY = """\
<wazuh_config>
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <key>REAL_CLUSTER_SECRET</key>
    <port>1516</port>
  </cluster>
</wazuh_config>"""


@patch('wazuh.rbac.decorators._can_read_secrets', return_value=False)
@patch('builtins.open', new_callable=mock_open, read_data=_MANAGER_CONF_WITH_CLUSTER_KEY)
def test_read_manager_conf_raw_masks_cluster_key_for_readonly(mock_file, mock_perms):
    """read_manager_conf(raw=True) hides cluster.key for users without update_config (readonly role)."""
    result = read_manager_conf(raw=True)

    assert isinstance(result, str), 'No expected result type'
    assert 'REAL_CLUSTER_SECRET' not in result
    assert '<key>*****</key>' in result


@patch('wazuh.rbac.decorators._can_read_secrets', return_value=True)
@patch('builtins.open', new_callable=mock_open, read_data=_MANAGER_CONF_WITH_CLUSTER_KEY)
def test_read_manager_conf_raw_no_masking_for_admin(mock_file, mock_perms):
    """read_manager_conf(raw=True) returns the real cluster key for admin users with update_config."""
    result = read_manager_conf(raw=True)

    assert isinstance(result, str), 'No expected result type'
    assert 'REAL_CLUSTER_SECRET' in result


@patch('wazuh.rbac.decorators._can_read_secrets', return_value=False)
@patch('builtins.open', new_callable=mock_open, read_data=_MANAGER_CONF_WITH_CLUSTER_KEY)
def test_read_manager_conf_raw_masking_does_not_corrupt_other_fields(mock_file, mock_perms):
    """Masking cluster.key must not corrupt other fields in the configuration."""
    result = read_manager_conf(raw=True)

    assert '<name>wazuh</name>' in result
    assert '<node_name>master-node</node_name>' in result
    assert '<port>1516</port>' in result


@patch('wazuh.core.common.os.chown')
@patch('wazuh.core.common.os.path.exists', return_value=True)
@patch('builtins.open', new_callable=mock_open, read_data='test-uuid')
@patch('wazuh.core.common.wazuh_gid', return_value=0)
@patch('wazuh.core.common.wazuh_uid', return_value=0)
def test_get_basic_info(mock_uid, mock_gid, mock_open_file, mock_exists, mock_chown):
    """Tests get_basic_info() function works as expected"""
    result = get_basic_info()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


_UPDATE_PATCHES = [
    ('wazuh.manager.safe_move', {}),
    ('wazuh.manager.remove', {}),
    ('wazuh.manager.exists', {'return_value': True}),
    ('wazuh.manager.full_copy', {}),
    ('wazuh.manager.load_manager_conf_text', {'return_value': {'cluster': {'name': 'wazuh'}}}),
    ('wazuh.manager.load_manager_conf', {'return_value': {'cluster': {'name': 'wazuh'}}}),
    ('wazuh.manager.check_protected_sections', {}),
    ('wazuh.manager.write_manager_conf', {}),
    ('wazuh.manager.validate_manager_conf', {'return_value': {'status': 'OK'}}),
]


@pytest.fixture
def update_mocks():
    """Every collaborator of update_manager_conf() mocked, keyed by function name."""
    from contextlib import ExitStack
    with ExitStack() as stack:
        yield {target.rsplit('.', 1)[1]: stack.enter_context(patch(target, **kwargs)) for target, kwargs in _UPDATE_PATCHES}


def test_update_manager_conf(update_mocks):
    """update_manager_conf() validates the new text (syntax, schema, protected sections), writes it and validates the file."""
    new_conf = "<wazuh_config>\n  <cluster>\n    <name>wazuh</name>\n  </cluster>\n</wazuh_config>\n"
    result = update_manager_conf(new_conf=new_conf)

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0
    update_mocks['load_manager_conf_text'].assert_called_once_with(new_conf)
    update_mocks['check_protected_sections'].assert_called_once()
    update_mocks['write_manager_conf'].assert_called_once_with(new_conf)
    update_mocks['validate_manager_conf'].assert_called_once()
    update_mocks['remove'].assert_called_once()


@pytest.mark.parametrize('new_conf, failing, error, expected_code', [
    (None, None, None, 1125),
    ("<wazuh_config>\n  <cluster>\n", 'load_manager_conf_text', WazuhError(1131), 1131),
    ("<wazuh_config><auth><use_password>maybe</use_password></auth></wazuh_config>", 'load_manager_conf_text',
     WazuhError(1130, '/auth/use_password'), 1130),
    ("<wazuh_config><indexer><hosts></hosts></indexer></wazuh_config>", 'check_protected_sections',
     WazuhError(1127, '/indexer'), 1127),
    ("<wazuh_config><cluster><name>wazuh</name></cluster></wazuh_config>", 'validate_manager_conf', None, 1125),
])
def test_update_manager_conf_ko(update_mocks, new_conf, failing, error, expected_code):
    """update_manager_conf() reports the first failing check, never writes when the text is rejected and restores the
    backup when the written file is refused by the validator."""
    if failing == 'validate_manager_conf':
        update_mocks[failing].return_value = {'status': 'ERROR'}
    elif failing:
        update_mocks[failing].side_effect = error

    result = update_manager_conf(new_conf=new_conf)

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == expected_code
    if failing != 'validate_manager_conf':
        update_mocks['write_manager_conf'].assert_not_called()
    update_mocks['safe_move'].assert_called_once()
