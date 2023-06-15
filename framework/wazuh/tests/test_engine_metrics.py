import pytest
from unittest.mock import MagicMock, patch

from wazuh import engine_metrics
from wazuh.core.exception import WazuhError, WazuhResourceNotFound, WazuhInternalError


@pytest.mark.parametrize('fields, expected', [
    ({'limit': 10},
        [
            {
                "type": "Counter",
                "name": "ConsumedEvents",
                "status": "enabled",
                "scope": "EventQueue",
            },
            {
                "status": "enabled",
                "scope": "EventQueue",
                "type": "Counter",
                "name": "QueuedEvents",
            },
            {
                "scope": "EventQueue",
                "type": "UpDownCounter",
                "name": "UsedQueue",
                "status": "enabled",
            },
            {
                "name": "ConsumedEventsPerSecond",
                "scope": "EventQueueDelta",
                "type": "Counter",
                "status": "enabled",
            }
        ]
    )
])
def test_get_instruments(fields, expected):
    # Create a mock WazuhSocketJSON instance and its methods
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'OK', 'value': expected}

    # Patch the WazuhSocketJSON class with the mock instance
    with patch('wazuh.engine_metrics.WazuhSocketJSON', return_value=mock_socket):
        # Call the function you want to test
        result = engine_metrics.get_instruments(**fields)

    # Assert the expected result
    assert result['data'] == expected


def test_enable_instrument_returns_ok():
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'OK'}

    with patch('wazuh.engine_metrics.WazuhSocketJSON', return_value=mock_socket):
        result = engine_metrics.enable_instrument('scope', 'instrument', True)
    assert result['message'] == 'OK'


@pytest.mark.parametrize(
    'scope, instrument, error_msg, expected_error, expected_code',
    [
        ('scope_example', 'instrument_example', 'The scope_example scope has not been created', WazuhResourceNotFound, 9000),
        ('scope_example', 'instrument_example', 'scope does not have instrument_example instrument', WazuhResourceNotFound, 9001),
        ('scope_example', 'instrument_example', 'Internal error', WazuhInternalError, 9002)
    ]
)
def test_enable_instrument_raises_error(scope, instrument, error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_metrics.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            result = engine_metrics.enable_instrument(scope, instrument, True)

            assert e._code == expected_code
