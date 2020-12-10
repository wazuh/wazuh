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

                from wazuh.core.cluster import utils
                from wazuh import WazuhError, WazuhException, WazuhInternalError
                from wazuh.core.results import WazuhResult


default_cluster_config = {
    'disabled': True,
    'node_type': 'master',
    'name': 'wazuh',
    'node_name': 'node01',
    'key': '',
    'port': 1516,
    'bind_addr': '0.0.0.0',
    'nodes': ['NODE_IP'],
    'hidden': 'no'
}


def test_read_cluster_config():
    """Verify that read_cluster function returns, in this case, the default configuration."""
    config = utils.read_cluster_config()
    assert config == default_cluster_config

    with patch('wazuh.core.cluster.utils.get_ossec_conf', side_effect=WazuhError(1001)):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    with patch('wazuh.core.cluster.utils.get_ossec_conf', side_effect=KeyError(1)):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    with patch('wazuh.core.cluster.utils.get_ossec_conf', return_value={'cluster': default_cluster_config}):
        utils.read_config.cache_clear()
        default_cluster_config.pop('hidden')
        default_cluster_config['disabled'] = 'no'
        config = utils.read_cluster_config()
        config_simple = utils.read_config()
        assert config == config_simple
        assert config == default_cluster_config

        default_cluster_config['node_type'] = 'client'
        config = utils.read_cluster_config()
        assert config == default_cluster_config

        default_cluster_config['disabled'] = 'None'
        with pytest.raises(WazuhError, match='.* 3004 .*'):
            utils.read_cluster_config()

        default_cluster_config['disabled'] = 'yes'
        config = utils.read_cluster_config()
        assert config == default_cluster_config

        default_cluster_config['port'] = 'None'
        with pytest.raises(WazuhError, match='.* 3004 .*'):
            utils.read_cluster_config()


def test_get_manager_status():
    """Check that get_manager function returns the manager status,
    for this test, the status can be stopped or failed."""
    status = utils.get_manager_status()
    for value in status.values():
        assert value == 'stopped'

    with patch('wazuh.core.cluster.utils.glob', return_value=['ossec-0.pid']):
        with patch('re.match', return_value='None'):
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'failed'


def test_get_cluster_status():
    """Check if cluster is enabled and if is running."""
    status = utils.get_cluster_status()
    assert {'enabled': 'no', 'running': 'no'} == status


def test_manager_restart():
    """Verify that manager_restart send to the manager the restart request."""
    with patch('wazuh.core.cluster.utils.open', side_effect=None):
        with patch('fcntl.lockf', side_effect=None):
            with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
                utils.manager_restart()

            with patch('wazuh.core.cluster.utils.exists', return_value=True):
                with pytest.raises(WazuhInternalError, match='.* 1902 .*'):
                    utils.manager_restart()

                with patch('socket.socket.connect', side_effect=None):
                    with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                        utils.manager_restart()

                    with patch('socket.socket.send', side_effect=None):
                        status = utils.manager_restart()
                        assert WazuhResult({'message': 'Restart request sent'}) == status


def test_get_cluster_items():
    """Verify the cluster files information."""
    utils.get_cluster_items.cache_clear()

    with patch('os.path.abspath', side_effect=FileNotFoundError):
        with pytest.raises(WazuhException, match='.* 3005 .*'):
            utils.get_cluster_items()

    items = utils.get_cluster_items()
    assert items == {'files': {'etc/': {'permissions': 416, 'source': 'master', 'files': ['client.keys'],
                                         'recursive': False, 'restart': False, 'remove_subdirs_if_empty': False,
                                         'extra_valid': False, 'description': 'client keys file database'},
                               'etc/shared/': {'permissions': 432, 'source': 'master', 'files': ['merged.mg'],
                                                'recursive': True, 'restart': False, 'remove_subdirs_if_empty': True,
                                                'extra_valid': False, 'description': 'shared configuration files'},
                               'var/multigroups/': {'permissions': 432, 'source': 'master', 'files': ['merged.mg'],
                                                     'recursive': True, 'restart': False,
                                                     'remove_subdirs_if_empty': True, 'extra_valid': False,
                                                     'description': 'shared configuration files'},
                               'etc/rules/': {'permissions': 432, 'source': 'master', 'files': ['all'],
                                               'recursive': True, 'restart': True, 'remove_subdirs_if_empty': False,
                                               'extra_valid': False, 'description': 'user rules'},
                               'etc/decoders/': {'permissions': 432, 'source': 'master', 'files': ['all'],
                                                  'recursive': True, 'restart': True, 'remove_subdirs_if_empty': False,
                                                  'extra_valid': False, 'description': 'user decoders'},
                               'etc/lists/': {'permissions': 432, 'source': 'master', 'files': ['all'],
                                               'recursive': True, 'restart': True, 'remove_subdirs_if_empty': False,
                                               'extra_valid': False, 'description': 'user CDB lists'},
                               'queue/agent-groups/': {'permissions': 432, 'source': 'master', 'files': ['all'],
                                                        'recursive': True, 'restart': False,
                                                        'remove_subdirs_if_empty': False, 'extra_valid': True,
                                                        'description': 'agents group configuration'},
                               'excluded_files': ['ar.conf', 'ossec.conf'],
                               'excluded_extensions': ['~', '.tmp', '.lock', '.swp']},
                     'intervals': {'worker': {'sync_integrity': 9, 'sync_files': 10, 'keep_alive': 60,
                                              'connection_retry': 10, 'max_failed_keepalive_attempts': 2},
                                   'master': {'recalculate_integrity': 8, 'check_worker_lastkeepalive': 60,
                                              'max_allowed_time_without_keepalive': 120},
                                   'communication': {'timeout_cluster_request': 20, 'timeout_api_request': 200,
                                                     'timeout_api_exe': 10, 'timeout_receiving_file': 120}},
                     'sync_options': {'get_agentinfo_newer_than': 1800}, 'distributed_api': {'enabled': True}}


def test_ClusterFilter():
    """Verify that ClusterFilter adds cluster related information into cluster logs"""
    cluster_filter = utils.ClusterFilter(tag='Cluster', subtag='config')
    record = utils.ClusterFilter(tag='Testing', subtag='config')
    record.update_tag(new_tag='Testing_tag')
    record.update_subtag(new_subtag='Testing_subtag')

    assert cluster_filter.filter(record=record)


def test_ClusterLogger():
    """Verify that ClusterLogger defines the logger used by wazuh-clusterd."""
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    cluster_logger = utils.ClusterLogger(foreground_mode=False, log_path=current_logger_path,
                                         tag='{asctime} {levelname}: [{tag}] [{subtag}] {message}', debug_level=1)
    cluster_logger.setup_logger()

    assert cluster_logger.logger.level == logging.DEBUG

    os.path.exists(current_logger_path) and os.remove(current_logger_path)
