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

#     handler.get_messages()


async def test_handler_send_request():
    """
    Test to make sure that the 'send_request' method is properly working
    """

    with patch('wazuh.core.cluster.common.Handler.msg_build', return_values=["some", "messages"]):
        with patch('wazuh.core.cluster.common.Handler.push'):
            with patch('asyncio.wait_for'):
                await handler.send_request(b'some bytes', b'some data')

    # with patch('wazuh.core.cluster.common.Handler.msg_build', return_values=["some", "messages"]):
    #     with pytest.raises(exception.WazuhClusterError, match=r'.* 3026 *.'):
    #         await handler.send_request(b'some bytes', b'some data')

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3018 *.'):
        await handler.send_request(b'some bytes', b'some data')
    
    
    
