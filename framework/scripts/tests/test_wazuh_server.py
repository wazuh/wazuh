# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import signal
import sys
from unittest.mock import Mock, call, patch

import pytest
import scripts.wazuh_server as wazuh_server
from scripts.tests.conftest import get_default_configuration
from wazuh.core import pyDaemonModule
from wazuh.core.common import CONFIG_SERVER_SOCKET_PATH
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.server import ValidateFilePathMixin

wazuh_server.pyDaemonModule = pyDaemonModule

with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
    default_config = get_default_configuration()
    CentralizedConfig._config = default_config


def test_set_logging():
    """Check and set the behavior of set_logging function."""
    import wazuh.core.server.utils as server_utils

    wazuh_server.server_utils = server_utils
    with patch.object(server_utils, 'ServerLogger'):
        assert wazuh_server.set_logging(debug_mode=0)


@pytest.mark.parametrize('root', [True, False])
@patch('subprocess.Popen')
def test_start_daemons(mock_popen, root):
    """Validate that `start_daemons` works as expected."""

    class LoggerMock:
        def __init__(self):
            pass

        def info(self, msg):
            pass

    wazuh_server.main_logger = LoggerMock()
    wazuh_server.debug_mode_ = 0
    pid = 2
    process_mock = Mock()
    attrs = {'poll.return_value': 0, 'wait.return_value': 0}
    process_mock.configure_mock(**attrs)
    mock_popen.return_value = process_mock

    with (
        patch.object(wazuh_server, 'main_logger') as main_logger_mock,
        patch.object(wazuh_server.pyDaemonModule, 'get_parent_pid', return_value=pid),
        patch.object(wazuh_server.pyDaemonModule, 'create_pid'),
    ):
        wazuh_server.start_daemons(root)

    mock_popen.assert_has_calls(
        [
            call([wazuh_server.ENGINE_BINARY_PATH, 'server', '-l', 'info', 'start']),
            call([wazuh_server.MANAGEMENT_API_SCRIPT_PATH] + (['-r'] if root else [])),
            call([wazuh_server.COMMS_API_SCRIPT_PATH] + (['-r'] if root else [])),
        ],
        any_order=True,
    )

    main_logger_mock.info.assert_has_calls(
        [
            call('Starting wazuh-engined'),
            call('Starting wazuh-comms-apid'),
            call('Starting wazuh-server-management-apid'),
        ]
    )


@patch('subprocess.Popen')
def test_start_daemons_ko(mock_popen):
    """Validate that `start_daemons` works as expected when the subprocesses fail."""

    class LoggerMock:
        def __init__(self):
            pass

        def info(self, msg):
            pass

    wazuh_server.main_logger = LoggerMock()
    wazuh_server.debug_mode_ = 0
    pid = 2
    wait_mock = Mock()
    process_mock = Mock()
    attrs = {'wait': wait_mock}
    process_mock.configure_mock(**attrs)
    mock_popen.return_value = process_mock

    with (
        patch.object(wazuh_server, 'main_logger'),
        patch.object(wazuh_server.pyDaemonModule, 'get_parent_pid', return_value=pid),
    ):
        with pytest.raises(wazuh_server.WazuhDaemonError, match='Error starting wazuh-engined: return code 1'):
            wait_mock.side_effect = (1,)
            wazuh_server.start_daemons(False)

        with pytest.raises(wazuh_server.WazuhDaemonError, match='Error starting wazuh-comms-apid: return code 1'):
            wait_mock.side_effect = (0, 1)
            wazuh_server.start_daemons(False)

        with pytest.raises(
            wazuh_server.WazuhDaemonError, match='Error starting wazuh-server-management-apid: return code 1'
        ):
            wait_mock.side_effect = (0, 0, 1)
            wazuh_server.start_daemons(False)

    mock_popen.assert_has_calls(
        [
            call([wazuh_server.ENGINE_BINARY_PATH, 'server', '-l', 'info', 'start']),
            call([wazuh_server.MANAGEMENT_API_SCRIPT_PATH]),
            call([wazuh_server.COMMS_API_SCRIPT_PATH]),
        ],
        any_order=True,
    )


@patch('scripts.wazuh_server.os.kill')
@patch('scripts.wazuh_server.os.getpid', return_value=999)
def test_shutdown_daemon(os_getpid_mock, os_kill_mock):
    """Validate that `shutdown_daemon` works as expected."""

    class LoggerMock:
        def __init__(self):
            pass

        def info(self, msg):
            pass

    wazuh_server.main_logger = LoggerMock()

    with (
        patch.object(wazuh_server, 'main_logger') as main_logger_mock,
        patch.object(wazuh_server.pyDaemonModule, 'get_parent_pid', return_value=os_getpid_mock.return_value),
    ):
        wazuh_server.shutdown_daemon(wazuh_server.MANAGEMENT_API_DAEMON_NAME)

    os_kill_mock.assert_called_once_with(999, signal.SIGTERM)
    main_logger_mock.info.assert_has_calls(
        [
            call(f'Shutting down {wazuh_server.MANAGEMENT_API_DAEMON_NAME} (pid: {os_getpid_mock.return_value})'),
        ]
    )


def test_initialize():  # NOQA
    """Check and set the behavior of initialize function."""

    class Arguments:
        def __init__(self, root):
            self.root = root

    args = Arguments(
        root=True,
    )

    with (
        patch('scripts.wazuh_server.start_daemons') as start_daemons_mock,
        patch('scripts.wazuh_server.start_unix_server') as start_unix_server_mock,
        patch('scripts.wazuh_server.ping_unix_socket') as ping_unix_socket_mock,
    ):
        wazuh_server.initialize(args)
        start_unix_server_mock.assert_called_once()
        ping_unix_socket_mock.assert_called_with(CONFIG_SERVER_SOCKET_PATH)
        start_daemons_mock.assert_called_with(args.root)


@pytest.mark.parametrize(
    'command,expected_args',
    [
        (
            'start',
            [
                'func',
                'root',
            ],
        ),
        ('stop', ['func']),
        ('status', ['func']),
    ],
)
def test_get_script_arguments(command, expected_args):
    """Set the wazuh_server script parameters."""
    from wazuh.core import common

    wazuh_server.common = common

    expected_args.extend(['version'])
    with patch('argparse._sys.argv', ['wazuh_server.py', command]):
        parsed_args = wazuh_server.get_script_arguments().parse_args()

        for arg in expected_args:
            assert hasattr(parsed_args, arg)


@patch('scripts.wazuh_server.sys.exit', side_effect=sys.exit)
@patch('scripts.wazuh_server.os.getpid', return_value=543)
@patch('scripts.wazuh_server.os.setgid')
@patch('scripts.wazuh_server.os.setuid')
@patch('scripts.wazuh_server.os.chmod')
@patch('scripts.wazuh_server.os.chown')
@patch('scripts.wazuh_server.os.path.exists', return_value=True)
@patch('builtins.print')
@pytest.mark.skip(reason='This test will be refactored')
def test_start(
    print_mock,
    path_exists_mock,
    chown_mock,
    chmod_mock,
    setuid_mock,
    setgid_mock,
    getpid_mock,
    exit_mock,
    mkdir_wazuh_dir_mock,
):
    """Check and set the behavior of the `start` function."""
    import wazuh.core.server.utils as server_utils
    from wazuh.core import common

    class Arguments:
        def __init__(self, config_file, test_config, foreground, root):
            self.config_file = config_file
            self.test_config = test_config
            self.foreground = foreground
            self.root = root

    class LoggerMock:
        def __init__(self):
            pass

        def info(self, msg):
            pass

        def error(self, msg):
            pass

    args = Arguments(config_file='test', test_config=True, foreground=False, root=False)
    wazuh_server.main_logger = LoggerMock()
    wazuh_server.args = args
    wazuh_server.common = common
    wazuh_server.cluster_utils = server_utils
    with (
        patch.object(common, 'wazuh_uid', return_value='uid_test'),
        patch.object(common, 'wazuh_gid', return_value='gid_test'),
        patch.object(wazuh_server.main_logger, 'error') as main_logger_mock,
        patch.object(wazuh_server.main_logger, 'info') as main_logger_info_mock,
    ):
        with pytest.raises(SystemExit):
            wazuh_server.start()
        main_logger_mock.assert_called_once()
        main_logger_mock.reset_mock()
        path_exists_mock.assert_any_call(wazuh_server.CLUSTER_LOG)
        chown_mock.assert_called_with(wazuh_server.CLUSTER_LOG, 'uid_test', 'gid_test')
        chmod_mock.assert_called_with(wazuh_server.CLUSTER_LOG, 432)
        exit_mock.assert_called_once_with(1)
        exit_mock.reset_mock()

        with patch('wazuh.core.cluster.cluster.check_cluster_config', side_effect=IndexError):
            with pytest.raises(SystemExit):
                wazuh_server.start()
            main_logger_mock.assert_called_once()
            exit_mock.assert_called_once_with(1)
            exit_mock.reset_mock()

        with patch('wazuh.core.cluster.cluster.check_cluster_config', return_value=None):
            with pytest.raises(SystemExit):
                wazuh_server.start()
            main_logger_mock.assert_called_once()
            exit_mock.assert_called_once_with(0)
            main_logger_mock.reset_mock()
            exit_mock.reset_mock()

            args.test_config = False
            wazuh_server.args = args
            with (
                patch('wazuh.core.cluster.cluster.clean_up') as clean_up_mock,
                patch('scripts.wazuh_server.clean_pid_files') as clean_pid_files_mock,
                patch('scripts.wazuh_server.start_daemons') as start_daemons_mock,
                patch.object(wazuh_server.pyDaemonModule, 'get_parent_pid', return_value=999),
                patch('os.kill') as os_kill_mock,
                patch.object(wazuh_server.pyDaemonModule, 'create_pid') as create_pid_mock,
                patch.object(wazuh_server.pyDaemonModule, 'delete_child_pids'),
                patch.object(wazuh_server.pyDaemonModule, 'delete_pid') as delete_pid_mock,
            ):
                wazuh_server.start()
                main_logger_mock.assert_any_call("Unhandled exception: name 'cluster_items' is not defined")
                main_logger_mock.reset_mock()
                clean_up_mock.assert_called_once()
                clean_pid_files_mock.assert_called_once_with('wazuh-server')
                setuid_mock.assert_called_once_with('uid_test')
                setgid_mock.assert_called_once_with('gid_test')
                getpid_mock.assert_called()
                os_kill_mock.assert_has_calls(
                    [
                        call(999, signal.SIGTERM),
                        call(999, signal.SIGTERM),
                    ]
                )
                create_pid_mock.assert_called_once_with('wazuh-server', 543)
                delete_pid_mock.assert_has_calls(
                    [
                        call('wazuh-server', 543),
                    ]
                )
                main_logger_info_mock.assert_has_calls(
                    [
                        call('Generating JWT signing key pair'),
                        call('Shutting down wazuh-engined (pid: 999)'),
                        call('Shutting down wazuh-server-management-apid (pid: 999)'),
                        call('Shutting down wazuh-comms-apid (pid: 999)'),
                    ]
                )
                start_daemons_mock.assert_called_once()

                args.foreground = True
                wazuh_server.start()
                print_mock.assert_called_once_with('Starting cluster in foreground (pid: 543)')

                wazuh_server.cluster_items = {}
                with patch('scripts.wazuh_server.master_main', side_effect=KeyboardInterrupt('TESTING')):
                    wazuh_server.start()
                    main_logger_info_mock.assert_any_call('SIGINT received. Shutting down...')

                with patch('scripts.wazuh_server.master_main', side_effect=MemoryError('TESTING')):
                    wazuh_server.start()
                    main_logger_mock.assert_any_call(
                        "Directory '/tmp' needs read, write & execution permission for 'wazuh-server' user"
                    )

                error_message = 'Some daemon fail to start'
                start_daemons_mock.side_effect = wazuh_server.WazuhDaemonError(error_message)
                wazuh_server.start()
                main_logger_mock.assert_any_call(error_message)

                with patch('scripts.wazuh_server.master_main', side_effect=RuntimeError('TESTING')):
                    wazuh_server.start()
                    main_logger_mock.assert_any_call('Main loop stopped.')


def test_stop_loop():
    """Check and set the behavior of wazuh_server `stop_loop` function."""
    loop_mock = Mock()
    wazuh_server.stop_loop(loop_mock)
    loop_mock.stop.assert_called_once()


@patch('scripts.wazuh_server.shutdown_server')
def test_sigterm_handler(shutdown_server_mock):
    """Check and set the behavior of wazuh_server `sigterm_handler` function."""
    server_pid = 1
    wazuh_server.sigterm_handler(signal.SIGTERM, 10, server_pid)
    shutdown_server_mock.assert_called_with(server_pid)


@patch('scripts.wazuh_server.os.kill')
def test_stop(os_mock):
    """Check and set the behavior of wazuh_server stop function."""
    from wazuh.core import common

    wazuh_server.common = common
    pid = 123

    with patch.object(pyDaemonModule, 'get_wazuh_server_pid', return_value=pid):
        wazuh_server.stop()

    os_mock.assert_called_once_with(pid, signal.SIGTERM)


def test_stop_ko():
    """Validate that `stop` works as expected when the server is not running."""
    from wazuh.core import common

    wazuh_server.common = common
    wazuh_server.main_logger = Mock()

    with patch.object(pyDaemonModule, 'get_wazuh_server_pid', side_effect=StopIteration):
        with pytest.raises(SystemExit, match='0'):
            wazuh_server.stop()

    wazuh_server.main_logger.warning.assert_called_once_with('Wazuh server is not running.')


@pytest.mark.parametrize(
    'daemons,expected',
    [
        (
            [
                wazuh_server.SERVER_DAEMON_NAME,
                wazuh_server.COMMS_API_DAEMON_NAME,
                wazuh_server.ENGINE_DAEMON_NAME,
                wazuh_server.MANAGEMENT_API_DAEMON_NAME,
            ],
            [
                f'{wazuh_server.SERVER_DAEMON_NAME} is running...',
                f'{wazuh_server.COMMS_API_DAEMON_NAME} is running...',
                f'{wazuh_server.ENGINE_DAEMON_NAME} is running...',
                f'{wazuh_server.MANAGEMENT_API_DAEMON_NAME} is running...',
            ],
        ),
        (
            [
                wazuh_server.COMMS_API_DAEMON_NAME,
                wazuh_server.ENGINE_DAEMON_NAME,
                wazuh_server.MANAGEMENT_API_DAEMON_NAME,
            ],
            [
                f'{wazuh_server.SERVER_DAEMON_NAME} is not running...',
                f'{wazuh_server.COMMS_API_DAEMON_NAME} is running...',
                f'{wazuh_server.ENGINE_DAEMON_NAME} is running...',
                f'{wazuh_server.MANAGEMENT_API_DAEMON_NAME} is running...',
            ],
        ),
        (
            [
                wazuh_server.SERVER_DAEMON_NAME,
                wazuh_server.COMMS_API_DAEMON_NAME,
            ],
            [
                f'{wazuh_server.SERVER_DAEMON_NAME} is running...',
                f'{wazuh_server.COMMS_API_DAEMON_NAME} is running...',
                f'{wazuh_server.ENGINE_DAEMON_NAME} is not running...',
                f'{wazuh_server.MANAGEMENT_API_DAEMON_NAME} is not running...',
            ],
        ),
    ],
)
def test_status(capsys, daemons, expected):
    """Check and set the behavior of wazuh_server `status` function."""
    from wazuh.core import common

    wazuh_server.common = common

    with patch.object(pyDaemonModule, 'get_running_processes', return_value=daemons):
        wazuh_server.status()

    captured = capsys.readouterr().out.split('\n')

    for e in expected:
        assert e in captured


@patch('scripts.wazuh_server.clean_pid_files')
def test_check_daemon(clean_pid_files_mock):
    """Check and set the behavior of wazuh_server `check_daemon` function."""
    proc_name = 'test_daemon'
    children_number = 3
    proc_mock = Mock(
        **{
            'status.return_value': wazuh_server.psutil.STATUS_SLEEPING,
            'name.return_value': proc_name,
            'children.return_value': [i for i in range(children_number)],
        }
    )
    processes = [proc_mock]

    wazuh_server.check_daemon(processes, proc_name, children_number)

    proc_mock.name.assert_called_once()
    proc_mock.status.assert_called_once()
    proc_mock.children.assert_called_once()
    clean_pid_files_mock.assert_not_called()


@patch('scripts.wazuh_server.clean_pid_files')
def test_check_daemon_ko_process_status(clean_pid_files_mock):
    """Validate that `check_daemon` works as expected when the process status is not the expected."""
    proc_name = 'test_daemon'
    children_number = 3
    proc_mock = Mock(
        **{
            'status.return_value': wazuh_server.psutil.STATUS_ZOMBIE,
            'name.return_value': proc_name,
            'children.return_value': [i for i in range(children_number)],
        }
    )
    processes = [proc_mock]
    wazuh_server.main_logger = Mock()

    wazuh_server.check_daemon(processes, proc_name, children_number)

    proc_mock.name.assert_called_once()
    proc_mock.status.assert_called_once()
    proc_mock.children.assert_not_called()
    clean_pid_files_mock.assert_called_with(proc_name)
    wazuh_server.main_logger.error.assert_called_with(
        f'Daemon `{proc_name}` is not running, stopping the whole server.'
    )


@patch('scripts.wazuh_server.clean_pid_files')
def test_check_daemon_ko_children_number(clean_pid_files_mock):
    """Validate that `check_daemon` works as expected when the children number is not the expected."""
    proc_name = 'test_daemon'
    children_number = 3
    proc_mock = Mock(
        **{
            'status.return_value': wazuh_server.psutil.STATUS_SLEEPING,
            'name.return_value': proc_name,
            'children.return_value': [i for i in range(children_number - 1)],
        }
    )
    proc_list = [proc_mock]

    with pytest.raises(
        wazuh_server.WazuhDaemonError,
        match=f'Daemon `{proc_name}` does not have the correct number of children process.',
    ):
        wazuh_server.check_daemon(proc_list, proc_name, children_number)

    proc_mock.name.assert_called_once()
    proc_mock.status.assert_called_once()
    proc_mock.children.assert_called_once()
    clean_pid_files_mock.assert_not_called()


@patch('scripts.wazuh_server.asyncio.sleep', side_effect=(None, StopAsyncIteration))
async def test_check_for_server_readiness(sleep_mock):
    """Check and set the behavior of wazuh_server `check_for_server_readiness` function."""
    wazuh_server.main_logger = Mock()

    proc_name = 'test_daemon'
    children_number = 3

    expected_state = {proc_name: children_number}
    child_proc_mock = Mock(
        **{
            'status.return_value': wazuh_server.psutil.STATUS_SLEEPING,
            'name.return_value': proc_name,
            'children.return_value': [i for i in range(children_number)],
        }
    )
    main_proc_mock = Mock(**{'children.return_value': [child_proc_mock]})

    await wazuh_server.check_for_server_readiness(main_proc_mock, expected_state)

    sleep_mock.assert_not_called()
    wazuh_server.main_logger.warning_assert_not_called()


@pytest.mark.parametrize('daemon_exists,children_number', [(False, 3), (True, 2)])
@patch('scripts.wazuh_server.asyncio.sleep', side_effect=(None, StopAsyncIteration))
async def test_check_for_server_readiness_ko(sleep_mock, daemon_exists, children_number):
    """Validate that `check_for_server_readiness` works as expected when server doesn't have the expected requirements."""
    wazuh_server.main_logger = Mock()

    proc_name = 'test_daemon'
    expected_children_number = 3

    expected_state = {proc_name: expected_children_number}
    child_proc_mock = Mock(
        **{
            'status.return_value': wazuh_server.psutil.STATUS_SLEEPING,
            'name.return_value': proc_name,
            'children.return_value': [i for i in range(children_number)],
        }
    )
    main_proc_mock = Mock(**{'children.return_value': [child_proc_mock] if daemon_exists else []})

    with pytest.raises(StopAsyncIteration):
        await wazuh_server.check_for_server_readiness(main_proc_mock, expected_state)

    sleep_mock.assert_any_call(10)
    wazuh_server.main_logger.warning.assert_any_call(
        "The Server doesn't meet the expected daemons state: {'test_daemon': False}. Sleeping until next checking..."
    )


@pytest.mark.asyncio
@patch('scripts.wazuh_server.stop_loop', side_effect=RuntimeError)
@patch('scripts.wazuh_server.check_for_server_readiness')
@patch('scripts.wazuh_server.check_daemon', side_effect=(None, None, wazuh_server.WazuhDaemonError(code='Test error.')))
@patch('scripts.wazuh_server.asyncio.sleep')
async def test_monitor_server_daemons(sleep_mock, check_daemon_mock, readiness_mock, stop_loop_mock):
    """Check and set the behavior of wazuh_server `monitor_server_daemons` function."""
    wazuh_server.main_logger = Mock()
    comms_api_config_mock = Mock(workers=4)

    class MockObjectWithName:
        def __init__(self, name: str):
            self._name = name

        def name(self) -> str:
            return self._name

    proc_list = [
        MockObjectWithName('test_proc_1'),
        MockObjectWithName('test_proc_2'),
        MockObjectWithName('test_proc_3'),
    ]
    process_mock = Mock(**{'children.return_value': proc_list})
    loop_mock = Mock()

    with patch('scripts.wazuh_server.CentralizedConfig.get_comms_api_config', return_value=comms_api_config_mock):
        with pytest.raises(RuntimeError):
            await wazuh_server.monitor_server_daemons(loop=loop_mock, server_process=process_mock)

    readiness_mock.assert_called_once_with(
        process_mock,
        {
            wazuh_server.MANAGEMENT_API_DAEMON_NAME[:15]: 5,
            wazuh_server.COMMS_API_DAEMON_NAME: 8,
            wazuh_server.ENGINE_DAEMON_NAME: 0,
        },
    )

    check_daemon_mock.assert_has_calls(
        [
            call(proc_list, wazuh_server.MANAGEMENT_API_DAEMON_NAME[:15], 5),
            call(proc_list, wazuh_server.COMMS_API_DAEMON_NAME, 8),
            call(proc_list, wazuh_server.ENGINE_DAEMON_NAME, 0),
        ],
        any_order=True,
    )
    wazuh_server.main_logger.error.assert_called_with('Test error. Stopping the whole server.')
