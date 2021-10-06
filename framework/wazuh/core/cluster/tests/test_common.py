import hashlib
import json
import logging
import os
import asyncio
import sys
from unittest.mock import Mock, patch, MagicMock

import pytest
from wazuh.core import common, exception

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        import wazuh.core.cluster.common as cluster_common
        import wazuh.core.cluster.utils

# with patch('wazuh.common.getgrnam'):
#     with patch('wazuh.common.getpwnam'):
#         with patch('wazuh.common.wazuh_uid'):
#             with patch('wazuh.common.wazuh_gid'):
#                 sys.modules['wazuh.rbac.orm'] = MagicMock()

#                 from wazuh.core.cluster.cluster import get_node
#                 from wazuh.agent import get_agents_summary_status
#                 from wazuh.core.exception import WazuhError, WazuhInternalError
#                 from wazuh.core.manager import status
#                 from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
#                 from wazuh.core.cluster.common import WazuhJSONEncoder, as_wazuh_object

# affected = AffectedItemsWazuhResult(dikt={'data': ['test']}, affected_items=['001', '002'])
# affected.add_failed_item(id_='099', error=WazuhError(code=1750, extra_message='wiiiiiii'))
# affected.add_failed_item(id_='111', error=WazuhError(code=1750, extra_message='weeeeee'))
# affected.add_failed_item(id_='555', error=WazuhError(code=1750, extra_message='wiiiiiii'))
# affected.add_failed_item(id_='333', error=WazuhError(code=1707, extra_message='wiiiiiii'))

# with patch('wazuh.common.wazuh_path', new=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')):
#     objects_to_encode = [
#         {'foo': 'bar',
#          'foo2': 3,
#          'mycallable': get_node},
#         {'foo': 'bar',
#          'foo2': 3,
#          'mycallable': get_agents_summary_status},
#         {'foo': 'bar',
#          'foo2': 3,
#          'mycallable': status},
#         {'foo': 'bar',
#          'foo2': 3,
#          'exception': WazuhError(1500,
#                                  extra_message="test message",
#                                  extra_remediation="test remediation")},
#         {'foo': 'bar',
#          'foo2': 3,
#          'exception': WazuhInternalError(1000,
#                                          extra_message="test message",
#                                          extra_remediation="test remediation")},
#         {'foo': 'bar',
#          'foo2': 3,
#          'result': WazuhResult({'field1': 'value1', 'field2': 3}, str_priority=['KO', 'OK'])},
#         {'foo': 'bar',
#          'foo2': 3,
#          'result': affected}
#     ]


# @pytest.mark.parametrize('obj', objects_to_encode)
# @patch('wazuh.common.wazuh_path', new=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data'))
# def test_encoder_decoder(obj):
#     # Encoding first object
#     encoded = json.dumps(obj, cls=WazuhJSONEncoder)

#     # Decoding first object
#     obj_again = json.loads(encoded, object_hook=as_wazuh_object)
#     assert (obj_again == obj)


# Testing Response class methods

resp = cluster_common.Response()

async def test_response():
    """
    Test for the 'write' method that belongs to the Response class
    """

    with patch('asyncio.Event.wait') as wait_mock:
        with patch('asyncio.Event.set') as set_mock:
            await resp.read()
            resp.write(b"some content")

            wait_mock.assert_called_once()
            set_mock.assert_called_once()

# Testing InBuffer class methods

in_buffer = cluster_common.InBuffer()

def test_inbuffer_get_info_from_header():
    """
    Test the method 'get_info_from_header' that belongs to InBuffer class
    """

    with patch('struct.unpack', return_value=(0, 2048, b'pwd')) as unpack_mock:
        assert isinstance(in_buffer.get_info_from_header(b"header", "hhl", 1024), bytes)

        unpack_mock.assert_called_once()


def test_inbuffer_receive_data():
    """
    Test the 'receive_data' method that belongs to the InBuffer class
    """

    in_buffer = cluster_common.InBuffer()
    assert isinstance(in_buffer.receive_data(b"data"), bytes)

# Testing ReceiveStringTask methods

@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rst_str_method(logger_mock, wazuh_common_mock):
    """
    Test the '__str__' method

    Parameters
    ----------
        logger_mock : Mock Object
        wazuh_common_mock : Mock Object
    """

    with patch('wazuh.core.cluster.common.ReceiveStringTask.set_up_coro'):
        with patch('asyncio.create_task'):
            string_task = cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, b"task")
            string_task.__str__()


@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rst_set_up_coro(logger_mock, wazuh_common_mock):
    """
    Test the 'set_up_cor' method

    Parameters
    ----------
        logger_mock : Mock Object
        wazuh_common_mock : Mock Object
    """

    with pytest.raises(NotImplementedError):
        cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, b"task")


# TODO
# @patch('wazuh.core.cluster.common.WazuhCommon')
# @patch('logging.Logger')
# def test_rst_done_callback(logger_mock, wazuh_common_mock):
#     """
#     Test the 'done_callback' method

#     Parameters
#     ----------
#         logger_mock : Mock Object
#         wazuh_common_mock : Mock Object
#     """

#     with patch('wazuh.core.cluster.common.ReceiveStringTask.set_up_coro'):
#         with patch('asyncio.create_task'):
            
#             # with patch('wazuh.core.cluster.common.WazuhCommon') as wazuh_common_mock:
#                 # TODO: if self.task_id in self.wazuh_common.in_str: (line 176)

#             with patch('wazuh.core.cluster.common.WazuhCommon.task_id', return_value="task"):
#                 with patch('wazuh.core.cluster.common.WazuhCommon.sync_tasks', return_value={"task": b"task"}):
#                     with patch('wazuh.core.cluster.common.WazuhCommon'):
#                         string_task = cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, "task")
#                         string_task.done_callback()

# Testing ReceiveFileTask methods

@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rft_str_method(logger_mock, wazuh_common_mock):
    """
    Test the '__str__' method

    Parameters
    ----------
        logger_mock : Mock Object
        wazuh_common_mock : Mock Object
    """

    with patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro'):
        with patch('asyncio.create_task'):
            file_task = cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")
            file_task.__str__()


@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rft_set_up_coro(logger_mock, wazuh_common_mock):
    """
    Test the 'set_up_cor' method

    Parameters
    ----------
        logger_mock : Mock Object
        wazuh_common_mock : Mock Object
    """

    with pytest.raises(NotImplementedError):
        cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")

# TODO:
# @patch('wazuh.core.cluster.common.WazuhCommon')
# @patch('logging.Logger')
# def test_rft_done_callback(logger_mock, wazuh_common_mock):
#     """
#     Test the 'done_callback' method

#     Parameters
#     ----------
#         logger_mock : Mock Object
#         wazuh_common_mock : Mock Object
#     """

#     with patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro'):
#         with patch('asyncio.create_task'):
            
#             # with patch('wazuh.core.cluster.common.WazuhCommon') as wazuh_common_mock:
#                 # TODO: if self.task_id in self.wazuh_common.in_str: (line 176)

#             with patch('wazuh.core.cluster.common.WazuhCommon.task_id', return_value=b"task"):
#                 with patch('wazuh.core.cluster.common.WazuhCommon.sync_tasks', return_value={"task": b"task"}):
#                     with patch('wazuh.core.cluster.common.WazuhCommon'):
#                         file_task = cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, "task")
#                         file_task.done_callback()

# Testing Handler class methods
cluster_items = {"etc/": {"permissions": "0o640", "source": "master", "files": ["client.keys"],
                           "description": "client keys file database"},
                  "intervals": {"worker": {"sync_integrity": 9,
                                           "sync_agent_info": 10,
                                           "sync_agent_info_ko_retry": 1,
                                           "keep_alive": 60,
                                           "connection_retry": 10,
                                           "max_failed_keepalive_attempts": 2
                                           }, "master": {"recalculate_integrity": 8,
                                                         "check_worker_lastkeepalive": 60,
                                                         "max_allowed_time_without_keepalive": 120
                                                         }, "communication": {"timeout_cluster_request": 20,
                                                                              "timeout_dapi_request": 200,
                                                                              "timeout_receiving_file": 120
                                                                              }
                                }
                 }

handler = cluster_common.Handler("00000000000000000000000000000000", cluster_items)

def test_handler_push():
    """
    Test to make sure that the 'push' method is properly working
    """

    handler.transport = asyncio.WriteTransport
    with patch('asyncio.WriteTransport.write'):
        handler.push(b"message")


def test_handler_next_counter():
    """
    Test to make sure that the 'next_counter' method is properly working
    """

    assert isinstance(handler.next_counter(), int)


def test_handler_msg_build():
    """
    Test to make sure that the 'message_build' method is properly working
    """

    handler.msg_build(b"command", 12345, b"data")

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3024 .*'):
        handler.msg_build(b"much much longer command", 12345, b"data")

    handler.request_chunk = 100
    handler.msg_build(b"command", 12345, b"data")

    handler.request_chunk = 5242880


def test_handler_msg_parse():
    """
    Test to make sure that the 'msg_handler' method is properly wotking
    """

    assert handler.msg_parse() is False

    handler.in_buffer = b"much much longer command"
    assert handler.msg_parse() is True

    handler.in_msg.received = 1
    handler.in_buffer = b"command"
    assert handler.msg_parse() is True

# TODO
# def test_handler_get_messages():
#     """
#     Test to make sure that the 'get_messages' method is properly working
#     """

#     while handler:
#         handler.get_messages()


async def test_handler_send_request():
    """
    Test to make sure that the 'send_request' method is properly working
    """

    with patch('wazuh.core.cluster.common.Handler.msg_build', return_values=["some", "messages"]):
        with patch('wazuh.core.cluster.common.Handler.push'):
            with patch('asyncio.wait_for'):
                await handler.send_request(b'some bytes', b'some data')

    with patch('wazuh.core.cluster.common.Handler.msg_build', side_effect=MemoryError):
        with pytest.raises(exception.WazuhClusterError, match=r'.* 3026 *.'):
            await handler.send_request(b'some bytes', b'some data')

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3018 *.'):
        await handler.send_request(b'some bytes', b'some data')

    with patch('wazuh.core.cluster.common.Handler.msg_build', return_values=["some", "messages"]):
        with patch('wazuh.core.cluster.common.Handler.push'):
            with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError):
                await handler.send_request(b'some bytes', b'some data')


async def test_handler_send_file():
    """
    Test to make sure that the 'send_file' method is properly working
    """

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3034 *.'):
        await handler.send_file("some_file.txt")

    with patch('os.path.exists', return_value=True):
        with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"some data"):
            with patch('builtins.open'):
                with patch('hashlib.sha256'):
                    await handler.send_file("some_file.txt")


async def test_handler_send_string():
    """
    Test to make sure that the 'send_string' method is properly working
    """

    with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"some data"):
        await handler.send_string(b"something")

    with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"Error"):
        await handler.send_string(b"something")


def test_handler_get_manager():
    """
    Test to make sure that the 'get_manager' method is properly working
    """

    with pytest.raises(NotImplementedError):
        handler.get_manager()


# TODO
async def test_handler_forward_dapi_response():
    """
    Test to make sure that the 'forward_dapi_response' method is properly working
    """

    # with patch('wazuh.core.cluster.common.Handler.get_manager'):
    #     await handler.forward_dapi_response(b"client_name string_id")

    # with patch('wazuh.core.cluster.common.Handler.get_manager', side_effect=exception.WazuhException):
    #     with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"something") as send_request_mock:
    #         await handler.forward_dapi_response(b"client_name string_id")
    #         send_request_mock.assert_called_once()

    with patch('wazuh.core.cluster.common.Handler.get_manager', side_effect=Exception):
        with patch('wazuh.core.cluster.common.Handler.send_request'):
            await handler.forward_dapi_response(b"client_name string_id")

# TODO
async def test_handler_forward_sendsync_response():
    """
    Test to make sure that the 'forward_sendsync_response' method is properly working
    """

    with patch('wazuh.core.cluster.common.Handler.get_manager'):
        with patch('wazuh.core.cluster.common.Handler.send_request', return_value="some response"):
            await handler.forward_sendsync_response(b"client_name string_id")

    # with patch('wazuh.core.cluster.common.Handler.get_manager', side_effect=exception.WazuhException):
    #     with patch('wazuh.core.cluster.common.Handler.send_request', return_value="some response"):
    #         await handler.forward_sendsync_response(b"client_name string_id")

# TODO
# def test_handler_data_received():
#     """
#     Test to make sure that the 'data_received' function is properly working
#     """

#     with patch('wazuh.core.cluster.common.Handler.get_messages', return_value=(b"bytes1", 123, b"bytes2", b"bytes3")):
#         handler.data_received(b"message")


def test_handle_dispatch():
    """
    Test to make sure that the 'dispatch' function is properly working
    """

    with patch('wazuh.core.cluster.common.Handler.push'):
        with patch('wazuh.core.cluster.common.Handler.process_request', return_value=(b"command", b"payload")):
            handler.dispatch(b"command", 123, b"payload")

        # with patch('wazuh.core.cluster.common.Handler.process_request', return_value=wazuh.core.exception.WazuhException):
        #     handler.dispatch(b"command", 123, b"payload")
        
        with patch('wazuh.core.cluster.common.Handler.process_request', return_value=Exception):
            handler.dispatch(b"command", 123, b"payload")

# TODO
# def test_handler_close():
#     """
#     Test to make sure that the 'close' function is properly working
#     """

#     handler.transport = asyncio.WriteTransport
#     handler.close()


def test_handler_process_request():
    """
    Test to make sure that the 'process_request' function is properly working
    """

    with patch('wazuh.core.cluster.common.Handler.echo'):
        handler.process_request(b"echo", b"data")
    with patch('wazuh.core.cluster.common.Handler.receive_file'):
        handler.process_request(b"new_file", b"data")
    with patch('wazuh.core.cluster.common.Handler.receive_str'):
        handler.process_request(b"new_str", b"data")
    with patch('wazuh.core.cluster.common.Handler.update_file'):
        handler.process_request(b"file_upd", b"data")
    with patch('wazuh.core.cluster.common.Handler.str_upd'):
        handler.process_request(b"str_upd", b"data")
    with patch('wazuh.core.cluster.common.Handler.process_error_str'):
        handler.process_request(b"err_str", b"data")
    with patch('wazuh.core.cluster.common.Handler.end_file'):
        handler.process_request(b"file_end", b"data")
    with patch('wazuh.core.cluster.common.Handler.process_unknown_cmd'):
        handler.process_request(b"something random", b"data")


def test_handler_process_response():
    """
    Test to make sure that the 'process_response' function is properly working
    """

    assert handler.process_response(b'ok', b"payload") == b"payload"

    with patch('wazuh.core.cluster.common.Handler.process_error_from_peer', return_value=b"payload"):
        assert handler.process_response(b"err", b"payload") == b"payload"

    assert handler.process_response(b"command", b"payload") == b"Unkown response command received: command"


def test_handler_echo():
    """
    Test to make sure that the 'echo' function is properly working
    """

    assert handler.echo(b"data") == (b"ok", b"data")


def test_handler_receive_file():
    """
    Test to make sure that the 'receive_files' function is properly working
    """

    assert handler.receive_file(b"data") == (b"ok ", b"Ready to receive new file")


def test_handler_update_file():
    """
    Test to make sure that the 'update_files' function is properly working
    """

    with patch('builtins.open'):
        with open(os.path.join(os.getcwd(), "no_file.txt")) as f:
            handler.in_file = {b"filepath": {"fd": f, "checksum": hashlib.sha256()}}
            assert handler.update_file(b"filepath data") == (b"ok", b"File updated")


def test_handler_end_file():
    """
    Test to make sure that the 'end_file' function is properly working
    """

    with patch('builtins.open'):
        with open(os.path.join(os.getcwd(), "no_file.txt")) as f:
            handler.in_file = {b"name": {"fd": f, "checksum": hashlib.sha256()}}

            assert handler.end_file(b"name checksum") == (b"err",
                                                          b"File wasn't correctly received. Checksums aren't equal.")

    with patch('builtins.open'):
        with open(os.path.join(os.getcwd(), "no_file.txt")) as f:
            handler.in_file = {b"name": {"fd": f, "checksum": hashlib.sha256()}}

            assert handler.end_file(b"%s %s" % (b"name", hashlib.dige)) == (b"ok", b"File received correctly")

            with patch('hashlib.md5', return_value=b"checksum"):
                assert handler.end_file(b"name checksum") == (b"ok", b"File received correctly")