import pytest
from unittest.mock import MagicMock, patch

from wazuh import engine_metrics
from wazuh.core.exception import WazuhError, WazuhResourceNotFound, WazuhInternalError
from wazuh.core.engine.commands import MetricCommand

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
        ])
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
            engine_metrics.enable_instrument(scope, instrument, True)

            assert e._code == expected_code


@pytest.mark.parametrize(
    "data, expected",
    [
        (
            {
                "KVDB": None,
                "EventQueue": {
                    "ConsumedEvents": {
                        "schema": "",
                        "version": "",
                        "records": [
                            {
                                "unit": "",
                                "attributes": [{"value": 776, "type": "SumPointData"}],
                                "start_time": "Thu Jun  8 18:05:03 2023",
                                "type": "Counter",
                                "instrument_name": "ConsumedEvents",
                                "instrument_description": "",
                            }
                        ],
                    },
                    "QueuedEvents": {
                        "schema": "",
                        "records": [
                            {
                                "instrument_description": "",
                                "attributes": [{"value": 776, "type": "SumPointData"}],
                                "instrument_name": "QueuedEvents",
                                "unit": "",
                                "type": "Counter",
                                "start_time": "Thu Jun  8 " "18:05:03 " "2023",
                            }
                        ],
                        "version": "",
                    },
                },
                "EventQueueDelta": {
                    "ConsumedEventsPerSecond": {
                        "records": [
                            {
                                "start_time": "Thu Jun  8 18:05:03 2023",
                                "instrument_description": "",
                                "type": "Counter",
                                "instrument_name": "ConsumedEventsPerSecond",
                                "attributes": [{"value": 776, "type": "SumPointData"}],
                                "unit": "",
                            }
                        ],
                        "schema": "",
                        "version": "",
                    }
                },
            },
            [
                {
                    "schema": "",
                    "version": "",
                    "records": [
                        {
                            "unit": "",
                            "attributes": [{"value": 776, "type": "SumPointData"}],
                            "start_time": "Thu Jun  8 18:05:03 2023",
                            "type": "Counter",
                            "instrument_name": "ConsumedEvents",
                            "instrument_description": "",
                        }
                    ],
                    "scope_name": "EventQueue",
                },
                {
                    "schema": "",
                    "records": [
                        {
                            "instrument_description": "",
                            "attributes": [{"value": 776, "type": "SumPointData"}],
                            "instrument_name": "QueuedEvents",
                            "unit": "",
                            "type": "Counter",
                            "start_time": "Thu Jun  8 18:05:03 2023",
                        }
                    ],
                    "version": "",
                    "scope_name": "EventQueue",
                },
                {
                    "records": [
                        {
                            "start_time": "Thu Jun  8 18:05:03 2023",
                            "instrument_description": "",
                            "type": "Counter",
                            "instrument_name": "ConsumedEventsPerSecond",
                            "attributes": [{"value": 776, "type": "SumPointData"}],
                            "unit": "",
                        }
                    ],
                    "schema": "",
                    "version": "",
                    "scope_name": "EventQueueDelta",
                },
            ],
        )
    ],
)
def test_get_metrics_normalizes_the_data(data, expected):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None
    mock_socket.receive.return_value = {"status": "OK", "value": data}

    with patch("wazuh.engine_metrics.WazuhSocketJSON", return_value=mock_socket):
        result = engine_metrics.get_metrics(
            limit=10, scope_name="scope", instrument_name="instrument"
        )

        assert result["data"] == expected


@pytest.mark.parametrize('fields, expected_command', [
    ({'limit': 10}, MetricCommand.DUMP.value),
    ({'limit': 10, 'scope_name': 'a', 'instrument_name': 'b'}, MetricCommand.GET.value)
])
def test_get_metric_uses_correct_command(fields, expected_command):
    mock_socket = MagicMock()
    mock_socket.send = MagicMock()
    mock_socket.receive.return_value = {'status': 'OK', 'value': {}}

    with patch('wazuh.engine_metrics.WazuhSocketJSON', return_value=mock_socket):
        engine_metrics.get_metrics(**fields)
        assert mock_socket.send.call_args[0][0]['command'] == expected_command


@pytest.mark.parametrize(
    'scope, instrument, error_msg, expected_error, expected_code',
    [
        ('scope_example', 'instrument_example', 'The scope_example scope has not been created', WazuhResourceNotFound, 9000),
        ('scope_example', 'instrument_example', 'scope does not have instrument_example instrument', WazuhResourceNotFound, 9001),
        ('scope_example', 'instrument_example', 'Internal error', WazuhInternalError, 9002)
    ]
)
def test_get_metrics_raises_error_from_socket(scope, instrument, error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_metrics.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_metrics.get_metrics(limit=10, scope_name=scope, instrument_name=instrument)

            assert e._code == expected_code


@pytest.mark.parametrize(
    'scope, instrument, expected_error, expected_code',
    [
        (None, 'some', WazuhError, 9003),
        ('some', None, WazuhError, 9003)
    ])
def test_get_metrics_raises_error_with_invalid_args(scope, instrument, expected_error, expected_code):
    with pytest.raises(expected_error) as e:
        engine_metrics.get_metrics(limit=10, scope_name=scope, instrument_name=instrument)

        assert e._code == expected_code
