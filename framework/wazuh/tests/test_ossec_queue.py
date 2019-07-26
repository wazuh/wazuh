from unittest.mock import patch
import pytest

from wazuh.ossec_queue import OssecQueue
from wazuh.exception import WazuhException

@patch('wazuh.ossec_queue.OssecQueue._connect')
def test_OssecQueue__init__(mock_conn):
    """Tests OssecQueue.__init__ function works"""

    OssecQueue('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.ossec_queue.socket.socket.connect')
@patch('wazuh.ossec_queue.socket.socket.setsockopt')
def test_OssecQueue_protected_connect(mock_set, mock_conn):
    """Tests OssecQueue._connect function works"""

    OssecQueue('test_path')

    with patch('wazuh.ossec_queue.socket.socket.getsockopt', return_value=1):
        OssecQueue('test_path')

    mock_conn.assert_called_with('test_path')
    mock_set.assert_called_once_with(1, 7, 6400)


@patch('wazuh.ossec_queue.socket.socket.connect', side_effect=Exception)
def test_OssecQueue_protected_connect_ko(mock_conn):
    """Tests OssecQueue._connect function exceptions works"""

    with pytest.raises(WazuhException, match=".* 1010 .*"):
        OssecQueue('test_path')


@pytest.mark.parametrize('send_response, error', [
    (1, False),
    (0, True)
])
@patch('wazuh.ossec_queue.socket.socket.connect')
@patch('wazuh.ossec_queue.OssecQueue.MAX_MSG_SIZE', new=0)
def test_OssecQueue_protected_send(mock_conn, send_response, error):
    """Tests OssecQueue._send function works"""

    queue = OssecQueue('test_path')

    with patch('socket.socket.send', return_value=send_response):
        if error:
            with pytest.raises(WazuhException, match=".* 1011 .*"):
                queue._send('msg')
        else:
            queue._send('msg')

    mock_conn.assert_called_with('test_path')


@patch('wazuh.ossec_queue.socket.socket.connect')
@patch('wazuh.ossec_queue.OssecQueue.MAX_MSG_SIZE', new=0)
@patch('socket.socket.send', side_effect=Exception)
def test_OssecQueue_protected_send_ko(mock_send, mock_conn):
    """Tests OssecQueue._send function exceptions works"""

    queue = OssecQueue('test_path')

    with pytest.raises(WazuhException, match=".* 1011 .*"):
        queue._send('msg')

    mock_conn.assert_called_with('test_path')