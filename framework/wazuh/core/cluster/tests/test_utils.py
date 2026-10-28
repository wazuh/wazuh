# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.getgrnam'):
    with patch('wazuh.core.common.getpwnam'):
        with patch('wazuh.core.common.wazuh_uid'):
            with patch('wazuh.core.common.wazuh_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core.cluster import utils
                from wazuh.core.exception import WazuhError, WazuhException, WazuhInternalError, WazuhPermissionError, \
                    WazuhResourceNotFound
                from wazuh.core.results import WazuhResult

default_cluster_config = {
    'node_type': 'master',
    'name': 'wazuh',
    'node_name': 'node01',
    'key': 'fd3350b86d239654e34866ab3c4988a8',
    'port': 1516,
    'bind_addr': '127.0.0.1',
    'nodes': ['127.0.0.1'],
    'hidden': 'no'
}


def test_read_cluster_config():
    """read_cluster_config() returns the effective `cluster` section of etc/wazuh-manager.conf and maps read errors to 3006."""
    effective = dict(default_cluster_config, hidden=False)

    with patch('wazuh.core.cluster.utils.get_manager_conf', side_effect=WazuhError(1001)):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    # An unreadable configuration file is wrapped in 3006, not turned into a process exit.
    with patch('wazuh.core.cluster.utils.get_manager_conf', side_effect=Exception('broken conf')):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    with patch('wazuh.core.cluster.utils.get_manager_conf', side_effect=KeyError(1)):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    with patch('wazuh.core.cluster.utils.get_manager_conf', return_value={'cluster': effective}) as get_conf:
        utils.read_config.cache_clear()
        config = utils.read_cluster_config()
        assert config == effective
        assert config['hidden'] is False
        get_conf.assert_called_once_with(section='cluster', conf_file=utils.common.MANAGER_CONF)

        config_simple = utils.read_config()
        assert config == config_simple
        utils.read_config.cache_clear()

    with patch('wazuh.core.cluster.utils.get_manager_conf', side_effect=WazuhError(1130, '/cluster/port')):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    with patch('wazuh.core.cluster.utils.get_manager_conf', side_effect=KeyError(1)):
        with pytest.raises(WazuhError, match='.* 3006 .*'):
            utils.read_cluster_config()

    utils.read_config.cache_clear()


@patch('wazuh.core.cluster.utils.read_config', return_value={'node_type': 'master'})
def test_get_manager_status(mock_read_config):
    """Check that get_manager_status function returns the manager status.

    For this test, the status can be stopped or failed.
    """
    called = 0

    def exist_mock(path):
        if '.failed' in path and called == 0:
            return True
        elif '.restart' in path and called == 1:
            return True
        elif '.start' in path and called == 2:
            return True
        elif '/proc' in path and called == 3:
            return True
        else:
            return False

    status = utils.get_manager_status()
    for value in status.values():
        assert value == 'stopped'

    with patch('wazuh.core.cluster.utils.glob', return_value=['ossec-0.pid']):
        with patch('re.match', return_value='None'):
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'failed'

        # with patch('wazuh.core.cluster.utils.join', return_value='failed') as join_mock:
        with patch('wazuh.core.cluster.utils.os.path.exists', side_effect=exist_mock):
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'failed'

            called += 1
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'restarting'

            called += 1
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'starting'

            called += 1
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'running'


@pytest.mark.parametrize('node_type, apid_reported', [
    ('master', True),
    ('worker', False)
])
def test_get_manager_status_apid(node_type, apid_reported):
    """Check that the API daemon is only reported on master nodes.

    Parameters
    ----------
    node_type : str
        Cluster node type of the reporting node.
    apid_reported : bool
        Whether the API daemon is expected in the returned status.
    """
    with patch('wazuh.core.cluster.utils.read_config', return_value={'node_type': node_type}):
        assert ('wazuh-manager-apid' in utils.get_manager_status()) == apid_reported


@pytest.mark.parametrize('exc', [
    PermissionError,
    FileNotFoundError
])
@patch('os.stat')
def test_get_manager_status_ko(mock_stat, exc):
    """Check that get_manager_status function correctly handles expected exceptions.

    Parameters
    ----------
    exc : Exception
        Expected exception to be handled.
    """
    mock_stat.side_effect = exc
    with pytest.raises(WazuhInternalError, match='.* 1913 .*'):
        utils.get_manager_status()


def test_get_cluster_status():
    """Check if cluster is enabled and running. Also check that cluster is shown as not running when a
    WazuhInternalError is raised."""
    status = utils.get_cluster_status()
    assert {'running': 'no'} == status

    with patch('wazuh.core.cluster.utils.get_manager_status', side_effect=WazuhInternalError(1913)):
        status = utils.get_cluster_status()
        assert {'running': 'no'} == status


@pytest.mark.parametrize('function, action, message', [
    (utils.manager_restart, 'restart', 'Restart request sent'),
    (utils.manager_reload, 'reload', 'Reload request sent'),
])
def test_manager_restart_reload_control_socket(function, action, message):
    """With the control socket available, the action is sent there and its answer must start with 'ok'."""
    with patch('wazuh.core.cluster.utils.open', side_effect=None), patch('fcntl.lockf', side_effect=None), \
            patch('os.path.exists', return_value=True), \
            patch('wazuh.core.cluster.utils._run_service_control') as run_helper, \
            patch('socket.socket.connect', side_effect=None), patch('socket.socket.close', side_effect=None):
        # send/recv fails (socket error)
        with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
            function()

        with patch('socket.socket.send', side_effect=None) as send:
            # Response doesn't start with 'ok'
            with patch('socket.socket.recv', return_value=b'err Service control rejected action\n'):
                with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                    function()

            with patch('socket.socket.recv', return_value=b'ok accepted\n'):
                assert WazuhResult({'message': message}) == function()
            send.assert_called_with(action.encode())

    run_helper.assert_not_called()


HELPER_ACCEPT = """#!/bin/sh
echo "$@" > "$0.args"
[ "$(cut -d' ' -f5 /proc/$$/stat)" = "$$" ] && echo yes > "$0.pgroup"
printf 1 >&3
exec 3>&-
{after}
"""


@pytest.fixture
def service_control(tmp_path):
    """Install a stand-in service-control helper under a temporary installation directory.

    Returns a function that writes the helper's body and gives its path.
    """
    (tmp_path / 'bin').mkdir()
    (tmp_path / 'var' / 'run').mkdir(parents=True)
    helper = tmp_path / 'bin' / utils.SERVICE_CONTROL_NAME

    def write(body):
        helper.write_text(body)
        helper.chmod(0o755)
        return helper

    with patch('wazuh.core.common.WAZUH_PATH', str(tmp_path)), \
            patch('wazuh.core.common.CONTROL_SOCKET', str(tmp_path / 'queue' / 'sockets' / 'control.sock')), \
            patch('wazuh.core.cluster.utils.api_operation_lockfile', str(tmp_path / 'var' / 'run' / '.lock')), \
            patch('wazuh.core.cluster.utils.threading.Thread',
                  side_effect=lambda target, args, daemon: MagicMock(start=lambda: target(*args))):
        yield write


@pytest.mark.parametrize('function, action, message', [
    (utils.manager_restart, 'restart', 'Restart request sent'),
    (utils.manager_reload, 'reload', 'Reload request sent'),
])
def test_manager_restart_reload_without_control_socket(service_control, function, action, message):
    """Without the control socket, the action is run through the service-control helper, in its own process group."""
    helper = service_control(HELPER_ACCEPT.format(after='exit 0'))

    assert WazuhResult({'message': message}) == function()
    assert open(f'{helper}.args').read().strip() == action
    assert open(f'{helper}.pgroup').read().strip() == 'yes'


def test_manager_restart_helper_spawn_without_setsid(service_control):
    """The helper is spawned with attributes every interpreter supports.

    The bundled interpreter is built without POSIX_SPAWN_SETSID, so `posix_spawn(..., setsid=True)` raises
    NotImplementedError there. Simulate that interpreter on any host: the fallback must still run the helper.
    """
    helper = service_control(HELPER_ACCEPT.format(after='exit 0'))
    real_posix_spawn = os.posix_spawn

    def posix_spawn_without_setsid(*args, **kwargs):
        if kwargs.get('setsid'):
            raise NotImplementedError('posix_spawn: setsid unavailable on this platform')
        return real_posix_spawn(*args, **kwargs)

    with patch('wazuh.core.cluster.utils.os.posix_spawn', side_effect=posix_spawn_without_setsid):
        assert WazuhResult({'message': 'Restart request sent'}) == utils.manager_restart()

    assert open(f'{helper}.args').read().strip() == 'restart'


def test_manager_restart_helper_spawn_not_implemented(service_control):
    """A spawn attribute the interpreter lacks is a 1903 internal error, never an unhandled exception."""
    service_control(HELPER_ACCEPT.format(after='exit 0'))

    with patch('wazuh.core.cluster.utils.os.posix_spawn', side_effect=NotImplementedError('unavailable')), \
            pytest.raises(WazuhInternalError, match='.* 1903 .*') as exc:
        utils.manager_restart()

    assert 'unavailable' in exc.value.message


def test_manager_restart_connection_refused(service_control, tmp_path):
    """A control socket that refuses the connection (modulesd is gone) also falls back to the helper."""
    helper = service_control(HELPER_ACCEPT.format(after='exit 0'))
    stale = tmp_path / 'queue' / 'sockets' / 'control.sock'
    stale.parent.mkdir(parents=True)
    stale.write_text('')

    assert WazuhResult({'message': 'Restart request sent'}) == utils.manager_restart()
    assert open(f'{helper}.args').read().strip() == 'restart'


@pytest.mark.parametrize('function, action', [(utils.manager_restart, 'restart'), (utils.manager_reload, 'reload')])
def test_manager_restart_reload_helper_refuses(service_control, function, action):
    """A refusal of the helper is a 1904 error that names the action, the exit code and the helper's reason."""
    service_control('#!/bin/sh\necho "wazuh-manager-service-control: unauthorized caller" >&2\nexit 1\n')

    with pytest.raises(WazuhError, match='.* 1904 .*') as exc:
        function()

    assert exc.value.message == (f'The manager service-control helper refused the {action} request '
                                 '(exit code 1: wazuh-manager-service-control: unauthorized caller)')


def test_manager_restart_helper_no_answer(service_control):
    """A helper that neither accepts nor exits within the timeout is killed and reported."""
    service_control('#!/bin/sh\nexec sleep 30\n')

    with patch('wazuh.core.cluster.utils.SERVICE_CONTROL_TIMEOUT', 0.2), \
            pytest.raises(WazuhError, match='.* 1904 .*') as exc:
        utils.manager_restart()

    assert 'no answer within 0.2 seconds' in exc.value.message


def test_manager_restart_helper_missing(service_control):
    """A helper that cannot be run is a 1903 internal error."""
    with pytest.raises(WazuhInternalError, match='.* 1903 .*') as exc:
        utils.manager_restart()

    assert utils.SERVICE_CONTROL_NAME in exc.value.message


@pytest.mark.parametrize('function, action', [(utils.manager_restart, 'restart'), (utils.manager_reload, 'reload')])
def test_manager_restart_reload_helper_check_refuses(service_control, function, action):
    """A refusal of the check the helper runs after accepting (before systemctl) is still answered as a 1904."""
    service_control(HELPER_ACCEPT.format(
        after='echo "wazuh-manager-service-control: the manager configuration or credentials check failed; '
              'the manager was not restarted" >&2\nexit 1'))

    with pytest.raises(WazuhError, match='.* 1904 .*') as exc:
        function()

    assert exc.value.message == (f'The manager service-control helper refused the {action} request (exit code 1: '
                                 'wazuh-manager-service-control: the manager configuration or credentials check '
                                 'failed; the manager was not restarted)')


def test_manager_restart_helper_fails_after_handing_over(service_control, caplog):
    """Once the helper has become what it runs (systemctl), the request is answered and a failure is only logged."""
    service_control(HELPER_ACCEPT.format(after="exec sh -c 'sleep 0.3; echo \"cannot restart\" >&2; exit 1'"))

    with caplog.at_level(logging.ERROR, logger='wazuh'):
        assert WazuhResult({'message': 'Restart request sent'}) == utils.manager_restart()

    assert 'The manager restart run by wazuh-manager-service-control failed (exit code 1): cannot restart' \
           in caplog.text


def test_manager_restart_helper_check_outlasts_the_wait(service_control, caplog):
    """A check longer than the wait does not hold the answer: the request is accepted and its outcome logged."""
    service_control(HELPER_ACCEPT.format(after='sleep 0.5\necho "check failed" >&2\nexit 1'))

    with patch('wazuh.core.cluster.utils.SERVICE_CONTROL_CHECK_TIMEOUT', 0.1), \
            caplog.at_level(logging.ERROR, logger='wazuh'):
        assert WazuhResult({'message': 'Restart request sent'}) == utils.manager_restart()

    assert 'failed (exit code 1): check failed' in caplog.text


def test_get_cluster_items():
    """Verify the cluster files information."""
    utils.get_cluster_items.cache_clear()

    with patch("os.path.abspath", side_effect=FileNotFoundError):
        with pytest.raises(WazuhException, match=".* 3005 .*"):
            utils.get_cluster_items()

    items = utils.get_cluster_items()

    expected = {
        "files": {
            "etc/": {
                "permissions": 416,
                "source": "master",
                "files": ["client.keys", "authd.pass", "enrollment_tokens.json"],
                "recursive": False,
                "restart": False,
                "remove_subdirs_if_empty": False,
                "extra_valid": False,
                "description": "client keys file database, enrollment shared password and enrollment tokens",
            },
            "etc/shared/": {
                "permissions": 432,
                "source": "master",
                "files": ["all"],
                "recursive": True,
                "restart": False,
                "remove_subdirs_if_empty": True,
                "extra_valid": False,
                "description": "shared configuration files",
            },
            "var/multigroups/": {
                "permissions": 432,
                "source": "master",
                "files": ["merged.mg"],
                "recursive": True,
                "restart": False,
                "remove_subdirs_if_empty": True,
                "extra_valid": False,
                "description": "shared configuration files",
            },
            "excluded_files": ["wazuh-manager.conf"],
            "excluded_extensions": ["~", ".tmp", ".lock", ".swp"],
        },
        "intervals": {
            "worker": {
                "sync_integrity": 9,
                "sync_agent_info": 10,
                "keep_alive": 60,
                "connection_retry": 10,
                "timeout_agent_groups": 40,
                "max_failed_keepalive_attempts": 2,
                "agent_groups_mismatch_limit": 5,
            },
            "common":{
                "active_response_polling": 30,
                "active_response_page_size": 1000,
                "active_response_event_grace": 120,
            },
            "master": {
                "timeout_extra_valid": 40,
                "recalculate_integrity": 8,
                "check_worker_lastkeepalive": 60,
                "max_allowed_time_without_keepalive": 120,
                "process_pool_size": 2,
                "sync_agent_groups": 10,
                "timeout_agent_info": 40,
                "max_locked_integrity_time": 1000,
                "agent_group_start_delay": 30,
                "sync_disconnected_agent_groups": 300,
                "sync_disconnected_agent_groups_batch_size": 100,
                "sync_disconnected_agent_groups_min_offline": 600,
                "sync_disconnected_agent_cluster_name_delay": 300,
                "metrics_frequency": 600,
                "metrics_bulk_size": 100,
            },
            "communication": {
                "timeout_cluster_request": 20,
                "timeout_dapi_request": 200,
                "timeout_receiving_file": 120,
                "min_zip_size": 31457280,
                "max_zip_size": 1073741824,
                "compress_level": 1,
                "zip_limit_tolerance": 0.2,
            },
        },
        "distributed_api": {"enabled": True},
    }

    assert json.dumps(items, sort_keys=True) == json.dumps(expected, sort_keys=True)


def test_ClusterFilter():
    """Verify that ClusterFilter adds cluster related information into cluster logs"""
    cluster_filter = utils.ClusterFilter(tag='Cluster', subtag='config')
    record = utils.ClusterFilter(tag='Testing', subtag='config')

    assert cluster_filter.filter(record=record)


def test_ClusterLogger():
    """Verify that ClusterLogger defines the logger used by wazuh-manager-clusterd."""
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    cluster_logger = utils.ClusterLogger(foreground_mode=False, log_path=current_logger_path,
                                         tag='%(asctime)s %(levelname)s: [%(tag)s] [%(subtag)s] %(message)s',
                                         debug_level=1)
    cluster_logger.setup_logger()

    assert cluster_logger.logger.level == logging.DEBUG

    os.path.exists(current_logger_path) and os.remove(current_logger_path)


def test_log_subprocess_execution():
    """Check that the passed messages from subprocesses are logged with the expected level."""
    logs = {'debug': {'example_debug': ["Debug level message."]},
            'debug2': {'example_debug2': ["Debug2 level message."]},
            'warning': {'example_debug2': ["Warning level message."]},
            'error': {'example_error': ["Error level message."]},
            'generic_errors': ['First generic error to be logged', 'Second generic error to be logged'],
            }
    with patch.object(utils.logger, 'debug') as debug_logger, \
            patch.object(utils.logger, 'debug2') as debug2_logger, \
            patch.object(utils.logger, 'warning') as warning_logger, \
            patch.object(utils.logger, 'error') as error_logger:
        utils.log_subprocess_execution(utils.logger, logs)
        debug_logger.assert_called_with(f"{dict(logs['debug'])}")
        debug2_logger.assert_called_with(f"{dict(logs['debug2'])}")
        warning_logger.assert_called_with(f"{dict(logs['warning'])}")
        error_logger.assert_any_call(f"{dict(logs['error'])}")
        for error in logs['generic_errors']:
            error_logger.assert_any_call(error, exc_info=False)


@patch('os.getpid', return_value=0000)
@patch('wazuh.core.cluster.utils.pyDaemonModule.create_pid')
def test_process_spawn_sleep(pyDaemon_create_pid_mock, get_pid_mock):
    """Check if the cluster pool is properly spawned."""

    child = 1
    utils.process_spawn_sleep(child)

    pyDaemon_create_pid_mock.assert_called_once_with(f'wazuh-manager-clusterd_child_{child}', get_pid_mock.return_value)


@pytest.mark.asyncio
@patch('concurrent.futures.ThreadPoolExecutor')
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI')
async def test_forward_function(distributed_api_mock, concurrent_mock):
    """Check if the function is correctly distributed to the master node."""

    class ThreadPoolExecutorMock:
        """Auxiliary class."""

        def submit(self, run, function):
            return DAPIMock()

    class DAPIMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def distribute_function(self):
            pass

        @staticmethod
        def result():
            return 'mock'

    def auxiliary_func():
        """Auxiliary function."""
        pass

    distributed_api_mock.return_value = DAPIMock()
    concurrent_mock.return_value = ThreadPoolExecutorMock()
    assert await utils.forward_function(auxiliary_func) == DAPIMock().result()
    distributed_api_mock.assert_called_once()
    concurrent_mock.assert_called_once()


@pytest.mark.parametrize('result', [
    WazuhError(6001),
    WazuhInternalError(1000),
    WazuhPermissionError(4000),
    WazuhResourceNotFound(1710),
    'value',
    1,
    False,
    {'key': 'value'}
])
def test_raise_if_exc(result):
    """Check that raise_if_exc raises an exception if the result is one."""
    if isinstance(result, Exception):
        with pytest.raises(Exception):
            utils.raise_if_exc(result)
    else:
        utils.raise_if_exc(result)

@pytest.mark.parametrize("base_dir", [
    "/absolute/dir",
    "/absolute/dir/",
    "relative/dir",
    "relative/dir/",
    "dir",
    "dir/",
])
@pytest.mark.parametrize("input_paths, should_raise", [
    (("sub/file.txt",), False),
    (("./file.txt",), False),
    (("", "file.txt"), False),
    (("../",), True),
    (("../../etc/passwd",), True),
    (("/etc/passwd",), False),
    (("///etc/passwd",), False),
    ((), False),
    (("../" + "dir_secrets",), True),
    (("sub", "..", ".."), True),
    ((".hidden",), False),
])
def test_safe_join(base_dir, input_paths, should_raise):
    if should_raise:
        with pytest.raises(WazuhInternalError):
            utils.safe_join(base_dir, *input_paths)
    else:
        result = utils.safe_join(base_dir, *input_paths)
        norm_base = os.path.normpath(base_dir)
        assert os.path.commonpath([norm_base, result]) == norm_base


INSTALLED_LAYOUT = {'wazuh.core.common.WAZUH_PATH': '/var/wazuh-manager', 'wazuh.core.common.CONF_PATH': '/etc/wazuh-manager'}
CHECKOUT_LAYOUT = {'wazuh.core.common.WAZUH_PATH': '/repo', 'wazuh.core.common.CONF_PATH': '/repo/etc'}


def _layout(layout):
    """Patch WAZUH_PATH and CONF_PATH with the given layout."""
    return patch.multiple('wazuh.core.common', **{k.rsplit('.', 1)[1]: v for k, v in layout.items()})


@pytest.mark.parametrize('layout', [INSTALLED_LAYOUT, CHECKOUT_LAYOUT])
@pytest.mark.parametrize('rel, conf_relative', [
    ('etc', ''),
    ('etc/', ''),
    ('etc/client.keys', 'client.keys'),
    ('etc/shared/', 'shared'),
    ('etc/shared/default/agent.conf', 'shared/default/agent.conf'),
    ('/etc/client.keys', 'client.keys'),
])
def test_local_path_maps_etc_to_conf_path(layout, rel, conf_relative):
    """Check that wire paths under 'etc' are rooted at CONF_PATH."""
    with _layout(layout):
        expected = os.path.normpath(os.path.join(layout['wazuh.core.common.CONF_PATH'], conf_relative))
        assert utils.local_path(rel) == expected


@pytest.mark.parametrize('layout', [INSTALLED_LAYOUT, CHECKOUT_LAYOUT])
@pytest.mark.parametrize('rel', ['var/multigroups/', 'var/multigroups/a/merged.mg', 'queue/cluster/x', 'etcetera/x',
                                 'etc.d/x'])
def test_local_path_maps_the_rest_to_wazuh_path(layout, rel):
    """Check that every other wire path is rooted at WAZUH_PATH ('etcetera' is not 'etc')."""
    with _layout(layout):
        assert utils.local_path(rel) == os.path.normpath(os.path.join(layout['wazuh.core.common.WAZUH_PATH'], rel))


@pytest.mark.parametrize('layout', [INSTALLED_LAYOUT, CHECKOUT_LAYOUT])
@pytest.mark.parametrize('rel', ['etc/../x', 'etc/..', 'etc/shared/../../queue/x', '../etc/passwd',
                                 'var/../../etc/passwd', 'etc/../../tmp/x'])
def test_local_path_refuses_traversal(layout, rel):
    """Check that a wire path escaping its root raises the same error safe_join() raises."""
    with _layout(layout):
        with pytest.raises(WazuhInternalError) as exc_info:
            utils.local_path(rel)
        assert exc_info.value.code == 3003


@pytest.mark.parametrize('layout', [INSTALLED_LAYOUT, CHECKOUT_LAYOUT])
@pytest.mark.parametrize('rel', ['etc', 'etc/', 'etc/client.keys', 'etc/shared/', 'etc/shared/default/agent.conf',
                                 'var/multigroups/', 'var/multigroups/a/merged.mg', 'queue/cluster/x'])
def test_wire_path_is_the_inverse_of_local_path(layout, rel):
    """Check that wire_path(local_path(x)) gives x back, keeping a directory key's trailing slash."""
    with _layout(layout):
        local = utils.local_path(rel)
        if rel.endswith('/'):
            local += os.sep
        assert utils.wire_path(local) == rel


@pytest.mark.parametrize('layout', [INSTALLED_LAYOUT, CHECKOUT_LAYOUT])
@pytest.mark.parametrize('abs_path', ['/tmp/x', '/', '/etc/passwd', '/var/wazuh-manager-other/x', '/repository/etc/x'])
def test_wire_path_refuses_paths_outside_both_roots(layout, abs_path):
    """Check that a path under neither CONF_PATH nor WAZUH_PATH has no wire path."""
    with _layout(layout):
        with pytest.raises(WazuhInternalError) as exc_info:
            utils.wire_path(abs_path)
        assert exc_info.value.code == 3003


def test_wire_path_prefers_conf_path_in_a_checkout():
    """In a repository checkout CONF_PATH is inside WAZUH_PATH; both resolve to the same 'etc' key."""
    with _layout(CHECKOUT_LAYOUT):
        assert utils.wire_path('/repo/etc/shared/default/agent.conf') == 'etc/shared/default/agent.conf'
