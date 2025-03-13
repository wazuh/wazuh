# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from asyncio import AbstractServer as AsyncioAbstractServer
from asyncio import Transport
from contextvars import ContextVar
from logging import Logger
from unittest.mock import ANY, AsyncMock, MagicMock, Mock, call, patch

import pytest
from freezegun import freeze_time
from uvloop import EventLoopPolicy
from wazuh.core.config.client import CentralizedConfig, Config
from wazuh.core.config.models.indexer import IndexerConfig, IndexerNode
from wazuh.core.config.models.server import NodeConfig, NodeType, ServerConfig, SSLConfig, ValidateFilePathMixin

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = Config(
                server=ServerConfig(
                    nodes=['0'],
                    node=NodeConfig(
                        name='node_name',
                        type=NodeType.MASTER,
                        ssl=SSLConfig(key='example', cert='example', ca='example'),
                    ),
                ),
                indexer=IndexerConfig(
                    hosts=[IndexerNode(host='example', port=1516)], username='wazuh', password='wazuh'
                ),
            )
            CentralizedConfig._config = default_config
        from wazuh.core.cluster.server import *
        from wazuh.core.exception import WazuhClusterError, WazuhError, WazuhResourceNotFound

asyncio.set_event_loop_policy(EventLoopPolicy())


@pytest.mark.asyncio
async def test_AbstractServerHandler_init(event_loop):
    """Check the correct initialization of the AbstractServerHandler object."""
    with patch('wazuh.core.cluster.server.context_tag', ContextVar('tag', default='')) as mock_contextvar:
        abstract_server_handler = AbstractServerHandler(
            server='Test', loop=event_loop, server_config=default_config.server
        )
        assert abstract_server_handler.server == 'Test'
        assert abstract_server_handler.loop == event_loop
        assert isinstance(abstract_server_handler.last_keepalive, float)
        assert abstract_server_handler.tag == 'Client'
        assert mock_contextvar.get() == 'Client'
        assert abstract_server_handler.name is None
        assert abstract_server_handler.ip is None
        assert abstract_server_handler.transport is None

        abstract_server_handler = AbstractServerHandler(
            server='Test',
            loop=event_loop,
            server_config=default_config.server,
            logger=Logger(name='test_logger'),
            tag='NoClient',
        )
        assert abstract_server_handler.server == 'Test'
        assert abstract_server_handler.loop == event_loop
        assert isinstance(abstract_server_handler.last_keepalive, float)
        assert abstract_server_handler.tag == 'NoClient'
        assert mock_contextvar.get() == 'NoClient'
        assert abstract_server_handler.handler_tasks == []
        assert isinstance(abstract_server_handler.broadcast_queue, asyncio.Queue)


@pytest.mark.asyncio
async def test_AbstractServerHandler_to_dict(event_loop):
    """Check the correct transformation of an AbstractServerHandler to a dict."""
    abstract_server_handler = AbstractServerHandler(server='Test', loop=event_loop, server_config=default_config.server)
    abstract_server_handler.ip = '111.111.111.111'
    abstract_server_handler.name = 'to_dict_testing'
    assert abstract_server_handler.to_dict() == {'info': {'ip': '111.111.111.111', 'name': 'to_dict_testing'}}


def test_AbstractServerHandler_connection_made(event_loop):
    """Check that the connection_made function correctly assigns the IP and the transport."""

    def get_extra_info(self, name):
        return ['peername', 'mock']

    transport = Transport()
    logger = Logger('test_connection_made')
    with patch('logging.getLogger', return_value=logger):
        with patch.object(logger, 'info') as mock_logger:
            abstract_server_handler = AbstractServerHandler(
                server='Test', loop=event_loop, server_config=default_config.server
            )
            with patch.object(asyncio.Transport, 'get_extra_info', get_extra_info):
                abstract_server_handler.connection_made(transport=transport)
                assert abstract_server_handler.ip == 'peername'
                assert abstract_server_handler.transport == transport
                mock_logger.assert_called_once_with("Connection from ['peername', 'mock']")


@pytest.mark.asyncio
@patch('wazuh.core.cluster.server.AbstractServerHandler.hello')
@patch('wazuh.core.cluster.server.AbstractServerHandler.echo_master')
@patch('wazuh.core.cluster.common.Handler.process_request')
async def test_AbstractServerHandler_process_request(mock_process_request, mock_echo_master, mock_hello, event_loop):
    """Check the behavior of the process_request function for the different commands that can be sent to it."""
    abstract_server_handler = AbstractServerHandler(server='Test', loop=event_loop, server_config=default_config.server)

    abstract_server_handler.process_request(command=b'echo-c', data=b'wazuh')
    mock_echo_master.assert_called_once_with(b'wazuh')

    abstract_server_handler.process_request(command=b'hello', data=b'hi')
    mock_hello.assert_called_once_with(b'hi')

    abstract_server_handler.process_request(command=b'process', data=b'request')
    mock_process_request.assert_called_once_with(b'process', b'request')


@pytest.mark.asyncio
@freeze_time('1970-01-01')
async def test_AbstractServerHandler_echo_master(event_loop):
    """Check that the echo_master function updates the last_keepalive variable and returns a confirmation message."""
    abstract_server_handler = AbstractServerHandler(server='Test', loop=event_loop, server_config=default_config.server)

    assert abstract_server_handler.echo_master(data=b'wazuh') == (b'ok-m ', b'wazuh')
    abstract_server_handler.echo_master(data=b'wazuh')
    assert abstract_server_handler.last_keepalive == 0.0


@patch('asyncio.create_task')
def test_AbstractServerHandler_hello(event_loop):
    """Check that the information of the new client invoking this function is stored correctly."""

    class ServerMock:
        def __init__(self):
            self.clients = {}
            self.configuration = {'node_name': 'elif_test'}

    event_loop.create_task = Mock()
    abstract_server_handler = AbstractServerHandler(server='Test', loop=event_loop, server_config=default_config.server)
    abstract_server_handler.server = ServerMock()
    abstract_server_handler.tag = 'FixBehaviour'
    abstract_server_handler.broadcast_reader = Mock()

    with patch('wazuh.core.cluster.server.context_tag', ContextVar('tag', default='')) as mock_contextvar:
        assert abstract_server_handler.hello(b'else_test') == (
            b'ok',
            f'Client {abstract_server_handler.name} added'.encode(),
        )
        assert abstract_server_handler.name == 'else_test'
        assert abstract_server_handler.server.clients['else_test'] == abstract_server_handler
        assert abstract_server_handler.tag == f'FixBehaviour {abstract_server_handler.name}'
        assert mock_contextvar.get() == abstract_server_handler.tag
        event_loop.create_task.assert_called_once()

    abstract_server_handler.server_config.node.name = 'fail_same_name'
    with pytest.raises(WazuhClusterError, match='.* 3029 .*'):
        abstract_server_handler.hello(b'fail_same_name')

    abstract_server_handler.name = 'if_test'
    abstract_server_handler.server.clients['if_test'] = 'testing'
    with pytest.raises(WazuhClusterError, match='.* 3028 .* if_test'):
        abstract_server_handler.hello(b'if_test')
    assert abstract_server_handler.name == ''


@pytest.mark.asyncio
@patch('wazuh.core.cluster.common.Handler.process_response')
async def test_AbstractServerHandler_process_response(process_response_mock, event_loop):
    """Check that the process_response function processes the response according to the command sent."""
    abstract_server_handler = AbstractServerHandler(server='Test', loop=event_loop, server_config=default_config.server)
    assert (
        abstract_server_handler.process_response(command=b'ok-c', payload=b'test')
        == b'Successful response from client: test'
    )

    abstract_server_handler.process_response(command=b'else', payload=b'test')
    process_response_mock.assert_called_once_with(b'else', b'test')


@pytest.mark.asyncio
async def test_AbstractServerHandler_connection_lost(event_loop):
    """Check that the process of client disconnection is done correctly. Removing all the information of this one."""

    class ServerMock:
        def __init__(self):
            self.clients = {'unit': 'test'}
            self.configuration = {'node_name': 'elif_test'}

    logger = Logger('test_connection_made')
    with patch('logging.getLogger', return_value=logger):
        abstract_server_handler = AbstractServerHandler(
            server='Test', loop=event_loop, server_config=default_config.server
        )
        with patch.object(logger, 'error') as mock_error_logger:
            abstract_server_handler.connection_lost(exc=None)
            mock_error_logger.assert_called_once_with(
                'Error during handshake with incoming connection.', exc_info=False
            )

        with patch.object(logger, 'error') as mock_error_logger:
            abstract_server_handler.connection_lost(exc=Exception('Test_connection_lost'))
            mock_error_logger.assert_called_once_with(
                'Error during handshake with incoming connection: Test_connection_lost. \n', exc_info=False
            )

        abstract_server_handler.name = 'unit'
        abstract_server_handler.server = ServerMock()
        with patch.object(logger, 'error') as mock_error_logger:
            abstract_server_handler.connection_lost(exc=Exception('Test_connection_lost_if'))
            mock_error_logger.assert_called_once_with(
                "Error during connection with 'unit': Test_connection_lost_if.\n", exc_info=False
            )
            assert 'unit' not in abstract_server_handler.server.clients.keys()

        with patch.object(logger, 'debug') as mock_debug_logger:
            task_mock = Mock()
            abstract_server_handler.handler_tasks = [task_mock]
            abstract_server_handler.connection_lost(exc=None)
            mock_debug_logger.assert_called_once_with('Disconnected unit.')
            task_mock.cancel.assert_called_once()


@pytest.mark.asyncio
@patch('asyncio.Queue')
@patch('wazuh.core.cluster.server.functools')
async def test_AbstractServerHandler_add_request(functools_mock, queue_mock, event_loop):
    """Check that requests are added to asyncio queue with expected parameters."""
    abstract_server_handler = AbstractServerHandler(server='Test', loop=event_loop, server_config=default_config.server)
    abstract_server_handler.add_request('test_id', 'test_f', 'test_param', keyword_param='test')
    queue_mock.return_value.put_nowait.assert_called_with({'broadcast_id': 'test_id', 'func': ANY})
    functools_mock.partial.assert_called_with('test_f', abstract_server_handler, 'test_param', keyword_param='test')


@pytest.mark.asyncio
async def test_AbstractServerHandler_broadcast_reader(event_loop):
    """Check that requests are read from the queue and executed with expected parameters."""

    async def async_mock_func():
        return 'Coroutine result'

    def sync_mock_func():
        return 'Result'

    server_mock = Mock()
    logger_mock = Mock()
    server_mock.broadcast_results = {'test1': {'worker1': {}}, 'test2': {'worker1': {}}, 'test3': {'worker1': {}}}
    abstract_server_handler = AbstractServerHandler(
        server=server_mock, loop=event_loop, server_config=default_config.server, logger=logger_mock
    )
    abstract_server_handler.name = 'worker1'

    with patch(
        'asyncio.Queue.get',
        side_effect=[
            {'broadcast_id': 'test1', 'func': async_mock_func},
            {'broadcast_id': 'test2', 'func': sync_mock_func},
            {'broadcast_id': 'test3', 'func': 'ko_func'},
            {'broadcast_id': None, 'func': sync_mock_func},
        ],
    ):
        with pytest.raises(Exception):
            await abstract_server_handler.broadcast_reader()
        assert server_mock.broadcast_results == {
            'test1': {'worker1': 'Coroutine result'},
            'test2': {'worker1': 'Result'},
            'test3': {'worker1': ANY},
        }
        logger_mock.error.assert_called_once_with(
            "Error while broadcasting function. ID: test3. Error: 'str' object is not callable."
        )


@patch('asyncio.get_running_loop', new=Mock())
@patch('wazuh.core.cluster.server.AbstractServer.check_clients_keepalive')
@patch('wazuh.core.cluster.server.AbstractServerHandler')
def test_AbstractServer_init(AbstractServerHandler_mock, keepalive_mock):
    """Check the correct initialization of the AbstractServer object."""
    with patch('wazuh.core.cluster.server.context_tag', ContextVar('tag', default='')) as mock_contextvar:
        abstract_server = AbstractServer(performance_test=1, concurrency_test=2, server_config=default_config.server)

        assert abstract_server.clients == {}
        assert abstract_server.performance == 1
        assert abstract_server.concurrency == 2
        assert abstract_server.tag == 'Abstract Server'
        assert mock_contextvar.get() == 'Abstract Server'
        assert isinstance(abstract_server.logger, Logger)

        logger = Logger('abs')
        abstract_server = AbstractServer(
            performance_test=1,
            concurrency_test=2,
            server_config=default_config.server,
            logger=logger,
            tag='test',
        )
        assert abstract_server.tag == 'test'
        assert mock_contextvar.get() == 'test'
        assert abstract_server.logger == logger
        assert abstract_server.broadcast_results == {}


@patch('asyncio.get_running_loop', new=Mock())
@patch('wazuh.core.cluster.server.AbstractServer.check_clients_keepalive')
@patch('wazuh.core.cluster.server.AbstractServerHandler')
def test_AbstractServer_broadcast(AbstractServerHandler_mock, asynckeepalive_mock):
    """Check that add_request is called with expected parameters."""

    def test_func():
        pass

    logger_mock = Mock()
    worker1_instance = Mock()
    worker2_instance = Mock()
    abstract_server = AbstractServer(
        performance_test=1,
        concurrency_test=2,
        server_config=default_config.server,
        logger=logger_mock,
    )
    abstract_server.clients = {'worker1': worker1_instance, 'worker2': worker2_instance}

    abstract_server.broadcast(test_func, 'test_param', keyword_param='param')
    worker1_instance.add_request.assert_called_once_with(None, ANY, 'test_param', keyword_param='param')
    worker2_instance.add_request.assert_called_once_with(None, ANY, 'test_param', keyword_param='param')
    logger_mock.debug2.call_args_list == [
        call('Added broadcast request to execute "test_func" in worker1.'),
        call('Added broadcast request to execute "test_func" in worker2.'),
    ]


@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_broadcast_ko():
    """Verify that expected error log is printed when an exception is raised."""
    logger_mock = Mock()
    abstract_server = AbstractServer(
        performance_test=1,
        concurrency_test=2,
        server_config=default_config.server,
        logger=logger_mock,
    )
    abstract_server.clients = {'worker1': 'test'}

    abstract_server.broadcast('test_f', 'test_param', keyword_param='param')
    logger_mock.error.assert_called_once_with(
        "Error while adding broadcast request in worker1: 'str' object has no attribute 'add_request'",
        exc_info=False,
    )


@patch('wazuh.core.cluster.server.uuid4', return_value='abc123')
@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_broadcast_add(uuid_mock):
    """Check that add_request is called with expected parameters."""

    def test_func():
        pass

    logger_mock = Mock()
    worker1_instance = Mock()
    worker2_instance = Mock()
    abstract_server = AbstractServer(
        performance_test=1,
        concurrency_test=2,
        server_config=default_config.server,
        logger=logger_mock,
    )
    abstract_server.broadcast_results = {}
    abstract_server.clients = {'worker1': worker1_instance, 'worker2': worker2_instance}

    assert abstract_server.broadcast_add(test_func, 'test_param', keyword_param='param') == 'abc123'
    assert abstract_server.broadcast_results == {'abc123': {'worker1': 'no_result', 'worker2': 'no_result'}}
    logger_mock.debug2.call_args_list == [
        call('Added broadcast request to execute "test_func" in worker1.'),
        call('Added broadcast request to execute "test_func" in worker2.'),
    ]


@patch('wazuh.core.cluster.server.uuid4', return_value='abc123')
@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_broadcast_add_ko(uuid_mock):
    """Check that expected error log is printed and that broadcast_results is deleted."""
    logger_mock = Mock()
    abstract_server = AbstractServer(
        performance_test=1,
        concurrency_test=2,
        server_config=default_config.server,
        logger=logger_mock,
    )
    abstract_server.broadcast_results = {}
    abstract_server.clients = {'worker1': 'test'}

    assert abstract_server.broadcast_add('test_f', 'test_param', keyword_param='param') is None
    logger_mock.error.assert_called_once_with(
        "Error while adding broadcast request in worker1: 'str' object has no attribute 'add_request'",
        exc_info=False,
    )
    assert abstract_server.broadcast_results == {}


@pytest.mark.parametrize(
    'broadcast_results, expected_response',
    [
        ({'abc123': {'worker1': 'no_result', 'worker2': 'no_result'}}, False),
        ({'abc123': {'worker1': 'Response', 'worker2': 'no_result'}}, False),
        ({'unknown': {}}, True),
        ({'abc123': {'worker1': 'Response', 'worker2': 'Response'}}, {'worker1': 'Response', 'worker2': 'Response'}),
        (
            {'abc123': {'worker1': 'Response', 'worker2': 'Response', 'worker3': 'Response'}},
            {'worker1': 'Response', 'worker2': 'Response', 'worker3': 'Response'},
        ),
    ],
)
@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_broadcast_pop(broadcast_results, expected_response):
    """Check that expected response is returned for each case."""
    logger_mock = Mock()
    abstract_server = AbstractServer(
        performance_test=1,
        concurrency_test=2,
        server_config=default_config.server,
        logger=logger_mock,
    )
    abstract_server.broadcast_results = broadcast_results
    abstract_server.clients = {'worker1': 'test', 'worker2': 'test'}

    assert abstract_server.broadcast_pop('abc123') == expected_response


@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_to_dict():
    """Check the correct transformation of an AbstractServer to a dict."""
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, server_config=default_config.server)
    assert abstract_server.to_dict() == {
        'info': {'ip': default_config.server.nodes[0], 'name': default_config.server.node.name}
    }


@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_setup_task_logger():
    """Check that a logger is created with a specific tag."""
    logger = Logger('setup_task_logger')
    abstract_server = AbstractServer(
        performance_test=1, concurrency_test=2, server_config=default_config.server, logger=logger
    )
    assert abstract_server.setup_task_logger(task_tag='zxf').name == 'setup_task_logger.zxf'

    with patch.object(abstract_server.logger, 'getChild') as mock_child:
        abstract_server.setup_task_logger(task_tag='fxz')
        mock_child.assert_called_with('fxz')


@patch('wazuh.core.cluster.server.utils.process_array')
@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_get_connected_nodes(mock_process_array):
    """Check that all the necessary data is sent to the utils.process_array
    function to return all the information of the connected nodes.
    """
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, server_config=default_config.server)
    basic_dict = {'info': {'first': 'test'}}

    with patch.object(abstract_server, 'to_dict', return_value=basic_dict):
        abstract_server.get_connected_nodes(
            search={'value': 'wazuh', 'negation': True},
            sort={'fields': ['nothing'], 'order': 'desc'},
            limit=501,
            offset=1,
        )
        mock_process_array.assert_called_once_with(
            [basic_dict['info']],
            search_text='wazuh',
            complementary_search=True,
            sort_by=['nothing'],
            sort_ascending=False,
            allowed_sort_fields=basic_dict['info'].keys(),
            offset=1,
            limit=501,
            distinct=False,
        )
        mock_process_array.reset_mock()


@patch('wazuh.core.cluster.server.utils.process_array')
@patch('asyncio.get_running_loop', new=Mock())
def test_AbstractServer_get_connected_nodes_ko(mock_process_array):
    """Check all exceptions that can be returned by the get_connected_nodes function."""
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, server_config=default_config.server)
    basic_dict = {'info': {'first': 'test'}}

    with patch.object(abstract_server, 'to_dict', return_value=basic_dict):
        abstract_server.get_connected_nodes()
        mock_process_array.assert_called_once_with(
            [basic_dict['info']],
            search_text=None,
            complementary_search=False,
            sort_by=None,
            sort_ascending=True,
            allowed_sort_fields=basic_dict['info'].keys(),
            offset=0,
            limit=500,
            distinct=False,
        )
        mock_process_array.reset_mock()

        with pytest.raises(WazuhError, match='.* 1724 .* Not a valid select field: no'):
            abstract_server.get_connected_nodes(select={'no': 'exists'})

        with pytest.raises(WazuhError, match='.* 1728 .*'):
            abstract_server.get_connected_nodes(filter_type='None')

        abstract_server.server_config.node.name = 'master'
        with pytest.raises(WazuhResourceNotFound, match='.* 1730 .*'):
            abstract_server.get_connected_nodes(filter_node='worker')


@pytest.mark.asyncio
@patch('asyncio.sleep', side_effect=IndexError)
@patch('asyncio.get_running_loop', new=Mock())
async def test_AbstractServer_check_clients_keepalive(sleep_mock):
    """Check that the function check_clients_keepalive checks the date of the
    last last_keepalive of the clients to verify if they are connected or not.
    """

    class TransportMock:
        def close(self):
            pass

    class ClientMock:
        def __init__(self):
            self.last_keepalive = 0
            self.transport = TransportMock()

    logger = Logger('test_check_clients_keepalive')
    with patch.object(logger, 'debug') as mock_debug:
        with patch.object(logger, 'error') as mock_error:
            with patch('wazuh.core.cluster.server.AbstractServer.setup_task_logger', return_value=logger):
                abstract_server = AbstractServer(
                    performance_test=1,
                    concurrency_test=2,
                    server_config=default_config.server,
                    logger=logger,
                )
                try:
                    await abstract_server.check_clients_keepalive()
                except IndexError:
                    pass
                mock_debug.assert_has_calls([call('Calculated.'), call('Calculating.')], any_order=True)
                sleep_mock.assert_called_once_with(default_config.server.master.intervals.check_worker_last_keep_alive)

                abstract_server.clients = {'worker_test': ClientMock()}
                try:
                    await abstract_server.check_clients_keepalive()
                except IndexError:
                    pass
                mock_error.assert_called_once_with(
                    'No keep alives have been received from worker_test in the last minute. Disconnecting',
                    exc_info=False,
                )


@pytest.mark.asyncio
@freeze_time('2022-01-01')
@patch('asyncio.sleep', side_effect=IndexError)
@patch('asyncio.get_running_loop', new=Mock())
@patch('wazuh.core.cluster.server.perf_counter', return_value=0)
async def test_AbstractServer_performance_test(perf_counter_mock, sleep_mock):
    """Check that the function performance_test sends a big message to all clients
    and then get the time it took to send them.
    """

    class ClientMock:
        async def send_request(self, command, data):
            return data * 10

    logger = Logger('test_echo')
    with patch.object(logger, 'info') as mock_info:
        abstract_server = AbstractServer(
            performance_test=1,
            concurrency_test=2,
            server_config=default_config.server,
            logger=logger,
        )
        abstract_server.clients = {b'worker_test': ClientMock()}
        abstract_server.performance = 2
        try:
            await abstract_server.performance_test()
        except IndexError:
            pass
        mock_info.assert_called_once_with('Received size: 20 // Time: 0')


@pytest.mark.asyncio
@freeze_time('2022-01-01')
@patch('asyncio.sleep', side_effect=IndexError)
@patch('asyncio.get_running_loop', new=Mock())
@patch('wazuh.core.cluster.server.perf_counter', return_value=0)
async def test_AbstractServer_concurrency_test(perf_counter_mock, sleep_mock):
    """Check that the function concurrency_test sends messages to all clients
    and then get the time it took to send them.
    """

    class ClientMock:
        async def send_request(self, command, data):
            pass

    logger = Logger('test_echo')
    with patch.object(logger, 'info') as mock_info:
        abstract_server = AbstractServer(
            performance_test=1,
            concurrency_test=2,
            server_config=default_config.server,
            logger=logger,
        )
        abstract_server.clients = {b'worker_test': ClientMock()}
        abstract_server.concurrency = 777
        try:
            await abstract_server.concurrency_test()
        except IndexError:
            pass
        mock_info.assert_called_once_with('Time sending 777 messages: 0')


@pytest.mark.asyncio
@patch('os.path.join', return_value='testing_path')
@patch('wazuh.core.cluster.server.AbstractServer.check_clients_keepalive')
async def test_AbstractServer_start(keepalive_mock, mock_path_join):
    """Check that the start function starts infinite asynchronous tasks according
    to the parameters with which the AbstractServer object has been created.
    """

    class SSLMock:
        def load_cert_chain(self):
            pass

    async def create_server(*args, **kwargs):
        server = AsyncioAbstractServer()
        server.sockets = [Mock()]
        patch.object(server.sockets[0], 'getsockname', return_value='socket')
        server.start = AsyncMock()
        server.close = Mock()
        server.wait_closed = AsyncMock()
        server.serve_forever = AsyncMock()
        return server

    logger = Logger('test_echo')

    loop = Mock()
    loop.create_server = AsyncMock(side_effect=create_server)
    loop.set_exception_handler = MagicMock()
    ssl_mock = SSLMock()
    cafile = default_config.server.node.ssl.ca
    certfile = default_config.server.node.ssl.cert
    keyfile = default_config.server.node.ssl.key
    password = default_config.server.node.ssl.keyfile_password

    abstract_server = AbstractServer(
        performance_test=1,
        concurrency_test=2,
        server_config=default_config.server,
        logger=logger,
    )
    with (
        patch('wazuh.core.cluster.server.context_tag', ContextVar('tag', default='')) as mock_contextvar,
        patch.object(abstract_server, 'handler_class'),
        patch('ssl.create_default_context', return_value=ssl_mock) as create_default_context_mock,
        patch.object(ssl_mock, 'load_cert_chain') as load_cert_chain_mock,
    ):
        abstract_server.loop = loop
        abstract_server.tag = 'start_test'
        await abstract_server.start()
        assert mock_contextvar.get() == 'start_test'
        loop.set_exception_handler.assert_called_once_with(c_common.asyncio_exception_handler)
        loop.create_server.assert_awaited_once()
        create_default_context_mock.assert_called_once_with(purpose=ssl.Purpose.CLIENT_AUTH, cafile=cafile)
        load_cert_chain_mock.assert_called_once_with(certfile=certfile, keyfile=keyfile, password=password)


@pytest.mark.asyncio
@patch('wazuh.core.cluster.server.AbstractServerHandler')
@patch('uvloop.EventLoopPolicy')
@patch('asyncio.set_event_loop_policy')
@patch('wazuh.core.cluster.server.AbstractServer.check_clients_keepalive')
async def test_AbstractServer_start_ko(
    keepalive_mock, set_event_loop_policy_mock, eventlooppolicy_mock, mock_AbstractServerHandler
):
    """Check for exceptions that may arise inside the start function."""

    class SSLMock:
        def load_cert_chain(self):
            pass

    class LoopMock:
        def set_exception_handler(self, handler):
            pass

        async def create_server(self, protocol_factory, host, port, ssl):
            raise OSError('test_start')

    logger = Logger('start')
    ssl_mock = SSLMock()

    with (
        patch('asyncio.get_running_loop', return_value=LoopMock()),
        patch('logging.getLogger', return_value=logger),
        patch.object(logger, 'error'),
        patch('ssl.create_default_context', return_value=ssl_mock),
        patch.object(ssl_mock, 'load_cert_chain'),
    ):
        with pytest.raises(exception.WazuhClusterError, match=r'.* 3007 .*'):
            abstract_server = AbstractServer(
                performance_test=1,
                concurrency_test=2,
                server_config=default_config.server,
                logger=logger,
            )
            await abstract_server.start()
