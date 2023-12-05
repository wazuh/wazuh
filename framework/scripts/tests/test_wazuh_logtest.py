#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import socket
import sys
from datetime import timedelta
from unittest.mock import patch, call

import pytest

import scripts.wazuh_logtest as wazuh_logtest


class WazuhSocketMock:
    """Auxiliary mock."""

    def __init__(self):
        self.request = None
        self.exception = False

    def send(self, request):
        self.request = request

        if not self.exception:
            return b''
        else:
            raise ConnectionError()


class WazuhDeamonProtocolMock:
    """Auxiliary mock."""

    def __init__(self):
        self.msg = None
        self.data = None
        self.recv_package = None
        self.reply = {'codemsg': 0, 'token': 'last token',
                      'output': {'rule': {'id': 1, 'level': 1}, 'decoder': {'name': 'name'}}}

    def wrap(self, msg, data):
        self.msg = msg
        self.data = data

        return ''

    def unwrap(self, recv_package):
        self.recv_package = recv_package

        return self.reply


@patch('argparse.ArgumentParser')
def test_init_argparse(argument_parser_mock):
    """Check if argparse is being properly handling command line parameters."""
    class ArgumentParserMock:
        """Auxiliary class."""
        def __init__(self):
            self.flag = []
            self.help = []
            self.action = []
            self.dest = []
            self.metavar = []
            self.default = []

        def add_argument(self, flag, help='', action='', dest='', metavar='', default=''):
            self.flag.append(flag)
            self.help.append(help)
            self.action.append(action)
            self.dest.append(dest)
            self.metavar.append(metavar)
            self.default.append(default)

    argument_parser_mock.return_value = ArgumentParserMock()
    wazuh_logtest.init_argparse()

    argument_parser_mock.assert_called_once_with(description='Tool for developing, tuning, and debugging rules.')
    assert argument_parser_mock.return_value.flag == ['-V', '-d', '-U', '-l', '-q', '-v']
    assert argument_parser_mock.return_value.help == ['Version and license message', 'Execute in debug mode',
                                                      'Unit test. Refer to ruleset/testing/runtests.py',
                                                      'Use custom location. Default "stdin"',
                                                      'Quiet execution', 'Verbose (full) output/rule debugging']
    assert argument_parser_mock.return_value.action == ['store_true', 'store_true', '', '', 'store_true', 'store_true']
    assert argument_parser_mock.return_value.dest == ['version', 'debug', 'ut', 'location', 'quiet', 'verbose']
    assert argument_parser_mock.return_value.metavar == ['', '', 'rule:alert:decoder', 'location', '', '']
    assert argument_parser_mock.return_value.default == ['', '', '', 'stdin', '', '']


@patch('sys.exit')
@patch('logging.info')
@patch('logging.error')
@patch('logging.warning')
@patch('atexit.register')
@patch('scripts.wazuh_logtest.init_logger')
@patch('scripts.wazuh_logtest.WazuhLogtest')
@patch('scripts.wazuh_logtest.init_argparse')
@patch('builtins.input', return_value='mock')
def test_main(input_mock, argparse_mock, wazuh_logtest_class_mock, init_logger_mock, register_mock, logger_warning_mock,
              logger_error_mock, logger_info_mock, sys_exit_mock):
    """Test the main function."""

    class ArgsMock:
        """Auxiliary class."""

        def __init__(self):
            self.ut = "mock:mock"
            self.version = "1.0.0"
            self.location = "World"
            self.verbose = True

    class ParserMock:
        """Auxiliary class."""

        def __init__(self):
            self.args = ArgsMock()

        def parse_args(self):
            return self.args

    class WazuhLogtestMock:
        """Auxiliary class."""

        def __init__(self, get_last_ut_mock=False, process_log_exception=None):
            self.location = None
            self.show_last_ut_result_called = False
            self.remove_last_session_called = False
            self.get_last_ut_called = False
            self.process_log_called = False
            self.get_last_ut_mock = get_last_ut_mock
            self.process_log_exception = process_log_exception

        def show_last_ut_result(self, ut):
            self.show_last_ut_result_called = True
            raise Exception("Break the 'while'")

        def remove_last_session(self):
            self.remove_last_session_called = True
            pass

        def get_last_ut(self):
            self.get_last_ut_called = True
            if not self.get_last_ut_mock:
                return "mock:mock"
            else:
                return ['3', '3', '3']

        def process_log(self, event, session_token, options):
            self.process_log_called = True
            if self.process_log_exception == 'ValueError':
                raise ValueError()
            elif self.process_log_exception == 'ConnectionError':
                raise ConnectionError()
            else:
                return {'token': 'sth', 'messages': ['WARNING']}

    argparse_mock.return_value = ParserMock()
    wazuh_logtest_class_mock.return_value = WazuhLogtestMock()

    # Test the first 'try' present in the 'while'
    try:
        wazuh_logtest.main()
    except Exception as e:
        pass

    argparse_mock.assert_called_once_with()
    init_logger_mock.assert_called_once_with(argparse_mock.return_value.args)
    input_mock.assert_called_once_with('\n')
    register_mock.assert_called_once_with(wazuh_logtest_class_mock.return_value.remove_last_session)
    sys_exit_mock.assert_has_calls([call(0), call(1)])

    logger_info_mock.assert_has_calls([call('%s', 'Wazuh ERROR - Wazuh Inc.'),
                                       call('%s', '\nThis program is free software; you can redistribute it and/or '
                                                  'modify\nit under the terms of the GNU General Public License '
                                                  '(version 2) as\npublished by the Free Software Foundation. For more '
                                                  'details, go to\nhttps://www.gnu.org/licenses/gpl.html\n'),
                                       call('Starting wazuh-logtest %s', 'ERROR'),
                                       call('Type one log per line')])
    logger_error_mock.assert_called_once_with('Unit test configuration wrong syntax: %s',
                                              wazuh_logtest_class_mock.return_value.get_last_ut())
    logger_warning_mock.assert_has_calls([call('** Wazuh-Logtest: %s', 'WARNING'), call('')])

    assert wazuh_logtest_class_mock.return_value.show_last_ut_result_called is True
    assert wazuh_logtest_class_mock.return_value.remove_last_session_called is False
    assert wazuh_logtest_class_mock.return_value.get_last_ut_called is True
    assert wazuh_logtest_class_mock.return_value.process_log_called is True

    # Test the first exception -> first condition
    input_mock.side_effect = EOFError()
    argparse_mock.return_value.args.ut = False
    argparse_mock.return_value.args.version = False

    try:
        wazuh_logtest.main()
    except Exception:
        pass

    sys_exit_mock.assert_called_with(0)

    # Test the first exception -> third condition
    argparse_mock.return_value.args.ut = '3:3:3'
    try:
        wazuh_logtest.main()
    except Exception:
        pass

    sys_exit_mock.assert_called_with(1)

    # Test the first exception -> second condition
    wazuh_logtest_class_mock.return_value = WazuhLogtestMock(True)

    try:
        wazuh_logtest.main()
    except Exception:
        pass

    # Test the second exception
    argparse_mock.return_value.args.ut = False
    input_mock.side_effect = None
    wazuh_logtest_class_mock.return_value = WazuhLogtestMock(process_log_exception='ValueError')
    logger_error_mock.side_effect = Exception()
    logger_error_mock.reset_mock()

    try:
        wazuh_logtest.main()
    except Exception:
        pass

    logger_error_mock.assert_called_once_with('** Wazuh-logtest error ')

    # Test the third exception
    logger_error_mock.reset_mock()
    wazuh_logtest_class_mock.return_value = WazuhLogtestMock(process_log_exception='ConnectionError')
    logger_error_mock.side_effect = Exception()

    try:
        wazuh_logtest.main()
    except Exception:
        pass

    logger_error_mock.assert_called_once_with('** Wazuh-logtest error when connecting with wazuh-analysisd')


# Test WazuhDaemonProtocol class methods

def create_wazuh_daemon_protocol_class():
    """Create new WazuhDaemonProtocol class."""
    return wazuh_logtest.WazuhDeamonProtocol()


def test_wdp_init():
    """Test the init method, checking the initial status of its attributes."""
    wdp = create_wazuh_daemon_protocol_class()

    assert isinstance(wdp.protocol, dict)
    assert wdp.protocol['version'] == 1
    assert isinstance(wdp.protocol['origin'], dict)
    assert wdp.protocol['origin']['name'] == 'wazuh-logtest'
    assert wdp.protocol['origin']['module'] == 'wazuh-logtest'


@patch('json.dumps', return_value='')
def test_wdp_wrap(json_dumps_mock):
    """Test if the data is being properly wrapped with wazuh daemon protocol information."""
    wdp = create_wazuh_daemon_protocol_class()
    assert wdp.wrap(command='command', parameters={'parameters': 'parameters'}) == json_dumps_mock.return_value
    json_dumps_mock.assert_called_once_with({'version': 1, 'origin': {'name': 'wazuh-logtest', 'module':
        'wazuh-logtest'}, 'command': 'command', 'parameters':
                                                 {'parameters': 'parameters'}})


@patch('json.loads', return_value={'error': 'error', 'message': 'message'})
def test_wdp_unwrap(json_loads_mock):
    """Test if the data is being properly unwrapped from the wazuh daemon protocol."""
    wdp = create_wazuh_daemon_protocol_class()
    msg = {}

    # Test if
    with pytest.raises(ValueError, match=f"{json_loads_mock.return_value['error']}: "
                                         f"{json_loads_mock.return_value['message']}") as e:
        wdp.unwrap(msg=msg)

    json_loads_mock.assert_called_once_with(msg)

    # Test the rest of the method
    json_loads_mock.return_value = {'data': 'data', 'error': ''}
    assert wdp.unwrap(msg) == json_loads_mock.return_value['data']


# Test WazuhSocket methods

def create_wazuh_socket_class(file):
    """Create a new WazuhSocket class."""
    return wazuh_logtest.WazuhSocket(file=file)


def test_ws_init():
    """Test the correct start of the WazuhSocket class."""
    file = ''
    assert create_wazuh_socket_class(file).file == file


@patch('socket.socket')
@patch('socket.AF_UNIX')
@patch('socket.SOCK_STREAM')
@patch('socket.MSG_WAITALL')
@patch('struct.pack', return_value=b'pack')
@patch('struct.unpack', return_value=[1, 'unpack'])
def test_ws_sent(unpack_mock, pack_mock, msg_waitall_mock, stream_mock, unix_mock, socket_socket_mock):
    """Test the correct data sending and reception."""

    class WLogtestConn:
        """Auxiliary class."""

        def __init__(self):
            self.connected = False
            self.sent = False
            self.received = False
            self.closed = False
            self.socket = []
            self.size = []
            self.msg = []

        def connect(self, file):
            self.connected = True

        def send(self, msg):
            self.msg.append(msg)
            self.sent = True

        def recv(self, size, socket):
            self.received = True
            self.socket.append(socket)
            self.size.append(size)
            return ''

        def close(self):
            self.closed = True

    file = ''
    socket_socket_mock.return_value = WLogtestConn()
    ws = create_wazuh_socket_class(file=file)

    # Test the try
    assert ws.send(file) == ''
    socket_socket_mock.assert_called_once_with(unix_mock, stream_mock)
    assert socket_socket_mock.return_value.connected is True
    pack_mock.assert_called_once_with('<I', 0)
    assert socket_socket_mock.return_value.sent is True
    unpack_mock.assert_called_once_with('<I', '')
    assert socket_socket_mock.return_value.closed is True
    assert socket_socket_mock.return_value.size == [4, 1]
    assert socket_socket_mock.return_value.socket == [msg_waitall_mock, msg_waitall_mock]

    # Test the exception
    socket_socket_mock.side_effect = Exception()

    with pytest.raises(ConnectionError):
        ws.send(file)


# Test WazuhLogtest class methods

@patch('scripts.wazuh_logtest.WazuhSocket', return_value=WazuhSocketMock())
@patch('scripts.wazuh_logtest.LOGTEST_SOCKET')
@patch('scripts.wazuh_logtest.WazuhDeamonProtocol', return_value=WazuhDeamonProtocolMock())
def create_wazuh_logtest_class(wazuh_deamon_mock, logtest_socket_mock, wazuh_socket_mock):
    """Create new WazuhLogtest class."""
    return wazuh_logtest.WazuhLogtest()


def test_wl_init():
    """Test the correct initialization of WazuhLogtest class."""
    wl = create_wazuh_logtest_class()

    assert isinstance(wl.protocol, WazuhDeamonProtocolMock)
    assert isinstance(wl.socket, WazuhSocketMock)
    assert wl.fixed_fields == {'location': 'stdin', 'log_format': 'syslog'}
    assert wl.last_token == ''
    assert wl.ut == ['', '', '']


@patch('logging.debug')
def test_wl_process_log(logging_debug_mock):
    """Check if we are processing a log correctly."""
    wl = create_wazuh_logtest_class()
    token = 'token'
    log = 'log'
    options = 'options'

    # Test a situation without errors
    assert wl.process_log(log=log, token=token, options=options) == wl.protocol.reply
    logging_debug_mock.assert_has_calls([call('Request: %s\n', ''), call('Reply: %s\n', '')])
    assert wl.protocol.msg == 'log_processing'
    assert wl.protocol.recv_package == b''
    assert wl.protocol.data == {'event': 'log', 'location': 'stdin', 'log_format': 'syslog', 'options': 'options',
                                'token': 'token'}
    assert wl.socket.request == ''

    # Test the exception
    wl.protocol.reply['codemsg'] = -1
    wl.protocol.reply['messages'] = ''

    with pytest.raises(ValueError, match=f"{wl.protocol.reply['codemsg']}: "):
        wl.process_log(log=log, token=token, options=options)


@patch('logging.debug')
def test_wl_remove_session(debug_mock):
    """Check if a session is correctly removed."""
    wl = create_wazuh_logtest_class()
    token = 'token'

    # Test the 'try' and first if
    assert not wl.remove_session(token=token)
    debug_mock.assert_called_once_with('Removing session with token %s.', 'token')
    assert not wl.socket.request
    assert wl.protocol.recv_package == b''
    assert wl.protocol.msg == 'remove_session'
    assert wl.protocol.data == {'location': 'stdin', 'log_format': 'syslog', 'token': 'token'}

    # Test the 'else'
    wl.protocol.reply['codemsg'] = 1
    assert wl.remove_session(token=token)

    # Test the exception
    wl.socket.exception = True
    assert not wl.remove_session(token=token)


@patch('scripts.wazuh_logtest.WazuhLogtest.remove_session')
def test_wl_remove_last_session(remove_session_mock):
    """Check if the last session is being correctly removed."""
    wl = create_wazuh_logtest_class()
    wl.last_token = 'last_token'

    wl.remove_last_session()
    remove_session_mock.assert_called_once_with(wl.last_token)


def test_wl_get_last_ut():
    """Check if the last known UT is being properly removed."""
    wl = create_wazuh_logtest_class()
    assert wl.get_last_ut() == wl.ut


@patch('logging.debug')
@patch('json.dumps', return_value='')
@patch('scripts.wazuh_logtest.WazuhLogtest.show_ossec_logtest_like')
def test_wl_show_output(show_ossec_logtest_like_mock, json_dumps_mock, debug_mock):
    """Check if the logtest is displaying the event processing."""
    wl = create_wazuh_logtest_class()
    wl.show_output()

    json_dumps_mock.assert_called_once()
    show_ossec_logtest_like_mock.assert_called_once()
    debug_mock.assert_called_once_with(json_dumps_mock.return_value)


@patch('logging.info')
@patch('scripts.wazuh_logtest.WazuhLogtest.show_phase_info')
def test_wl_show_ossec_logtest_like(show_phase_info_mock, info_mock):
    """Test if wazuh-logtest output is being shown as ossec-logtest output."""
    output = {'output': {'full_log': '', 'predecoder': 'predecoder_value', 'decoder': 'decoder_value', 'data': '',
                         'rule': 'rule_value'}, 'alert': 'alert_value', 'rules_debug': ['mock']}

    # Test the third 'if'
    wazuh_logtest.WazuhLogtest.show_ossec_logtest_like(output)
    info_mock.assert_has_calls([call('**Phase 1: Completed pre-decoding.'), call("\tfull event: '%s'", ''), call(''),
                                call('**Phase 2: Completed decoding.'), call(''), call('**Rule debugging:'),
                                call('\tmock'), call(''), call('**Phase 3: Completed filtering (rules).'),
                                call('**Alert to be generated.')])
    assert show_phase_info_mock.call_count == 4

    # Test the 'else'
    output['output'].pop('decoder')
    output.pop('rules_debug')
    output['output'].pop('rule')
    output['alert'] = ''
    info_mock.reset_mock()

    wazuh_logtest.WazuhLogtest.show_ossec_logtest_like(output)
    info_mock.assert_has_calls([call('**Phase 1: Completed pre-decoding.'), call(''),
                                call('**Phase 2: Completed decoding.'), call('\tNo decoder matched.')])
    assert show_phase_info_mock.call_count == 5


@patch('logging.info')
def test_wl_show_phase_info(info_mock):
    """Check if wazuh-logtest is processing phase information."""
    phase_data = {'key': 'value', 'key2': 'value2', 'key3': {'1': '2'}}
    show_first = ['key']

    wazuh_logtest.WazuhLogtest.show_phase_info(phase_data=phase_data, show_first=show_first)
    info_mock.assert_has_calls([call("\t%s: '%s'", 'key', 'value'), call("\t%s: '%s'", 'key2', 'value2')])


@patch('logging.info')
@patch('scripts.wazuh_logtest.WazuhLogtest.get_last_ut', return_value='mock')
def test_wl_show_last_result(get_last_ut_mock, info_mock):
    """Check if the unit test result is okay."""
    wl = create_wazuh_logtest_class()
    ut = 'mock'

    # Test the first condition
    wl.show_last_ut_result(ut=ut)
    info_mock.assert_has_calls([call(''), call('Unit test OK')])
    get_last_ut_mock.assert_called_once_with()

    # Test the second condition
    ut = 'not mock'
    get_last_ut_mock.reset_mock()
    info_mock.reset_mock()

    wl.show_last_ut_result(ut=ut)
    info_mock.assert_has_calls(
        [call(''), call('Unit test FAIL. Expected %s , Result %s', ut, get_last_ut_mock.return_value)])
    get_last_ut_mock.assert_called_with()
    assert get_last_ut_mock.call_count == 2


# Test Wazuh class

def create_wazuh_class():
    """Auxiliary function to create a Wazuh class."""
    return wazuh_logtest.Wazuh


@patch('scripts.wazuh_logtest.common.find_wazuh_path', return_value='')
def test_wazuh_get_install_path(find_wazuh_path_mock):
    """Test is we can get the installation path correctly."""
    assert create_wazuh_class().get_install_path() == find_wazuh_path_mock.return_value


@patch('subprocess.PIPE')
@patch('subprocess.Popen')
@patch('os.path.join', return_value='')
@patch('scripts.wazuh_logtest.Wazuh.get_install_path', return_value='')
def test_wazuh_get_info(get_install_mock, join_mock, popen_mock, pipe_mock):
    """Check if we can properly obtain information from wazuh-control."""

    class ProcMock:
        """Auxiliary class."""

        def __init__(self):
            self.communicated = False

        def communicate(self):
            self.communicated = True
            return [b'key=key\n', b'stderr']

    wazuh = create_wazuh_class()
    popen_mock.return_value = ProcMock()
    field = 'key'

    # Test the 'try'
    assert wazuh.get_info(field=field) == field
    get_install_mock.assert_called_once_with()
    join_mock.assert_called_once_with(get_install_mock.return_value, 'bin', 'wazuh-control')
    popen_mock.assert_called_once_with([join_mock.return_value, 'info'], stdout=pipe_mock)
    assert popen_mock.return_value.communicated is True

    # Test the 'except'
    popen_mock.side_effect = Exception()
    assert wazuh.get_info(field=field) == 'ERROR'


@patch('scripts.wazuh_logtest.Wazuh.get_info', return_value='')
def test_wazuh_get_version_str(get_info_mock):
    """Test if the version is being properly retrieved."""
    assert create_wazuh_class().get_version_str() == get_info_mock.return_value
    get_info_mock.assert_called_once_with('WAZUH_VERSION')


@patch('scripts.wazuh_logtest.Wazuh.get_version_str', return_value='')
def test_wazuh_get_description(get_version_mock):
    """Test if the description is being properly retrieved."""
    assert create_wazuh_class().get_description() == f"Wazuh {get_version_mock.return_value} - Wazuh Inc."
    get_version_mock.assert_called_once_with()


@patch('textwrap.dedent', return_value='')
def test_wazuh_get_license(dedent_mock):
    """Test that the license was not changed."""
    assert create_wazuh_class().get_license() == dedent_mock.return_value
    dedent_mock.assert_called_once_with('''
        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License (version 2) as
        published by the Free Software Foundation. For more details, go to
        https://www.gnu.org/licenses/gpl.html
        ''')


@patch('logging.basicConfig')
def test_init_logger(logging_mock):
    """Test the logger init function."""

    class ArgsMock:
        def __init__(self):
            self.debug = True
            self.quiet = True

    wazuh_logtest.init_logger(ArgsMock())

    logging_mock.assert_called_once_with(format='', level='ERROR')
