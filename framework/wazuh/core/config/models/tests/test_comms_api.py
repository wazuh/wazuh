import pytest
from pydantic import ValidationError

from wazuh.core.config.models.comms_api import BatcherConfig, CommsAPIIntervals, CommsAPIConfig


@pytest.mark.parametrize("init_values, expected", [
    ({}, {"max_elements": 5, "max_size": 3000, "wait_time": 0.15}),
    ({"max_elements": 2, "max_size": 200, "wait_time": 1}, {"max_elements": 2, "max_size": 200, "wait_time": 1})
])
def test_batcher_config_default_values(init_values, expected):
    """Check the correct initialization of the `BatcherConfig` class."""
    config = BatcherConfig(**init_values)

    assert config.max_elements == expected["max_elements"]
    assert config.max_size == expected["max_size"]
    assert config.wait_time == expected["wait_time"]


@pytest.mark.parametrize("init_values", [
    {"max_elements": -2},
    {"max_elements": 0},
    {"max_size": -10},
    {"max_size": 0},
    {"wait_time": -2},
    {"wait_time": 0}
])
def test_batcher_config_invalid_values(init_values):
    """Check the correct behavior of the `BatcherConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = BatcherConfig(**init_values)


@pytest.mark.parametrize("init_values, expected", [
    ({}, {"request_timeout": 10}),
    ({"request_timeout": 3}, {"request_timeout": 3})
])
def test_comms_api_intervals_default_values(init_values, expected):
    """Check the correct initialization of the `CommsAPIIntervals` class."""
    config = CommsAPIIntervals(**init_values)

    assert config.request_timeout == expected["request_timeout"]


@pytest.mark.parametrize("value", [
    -10,
    0
])
def test_comms_api_intervals_invalid_values(value):
    """Check the correct behavior of the `CommsAPIIntervals` class validations."""
    with pytest.raises(ValidationError):
        _ = CommsAPIIntervals(request_timeout=value)


@pytest.mark.parametrize("init_values, expected", [
    ({}, {"host": "localhost", "port": 27000, "workers": 4}),
    ({"host": "127.0.0.1", "port": 27001, "workers": 2}, {"host": "127.0.0.1", "port": 27001, "workers": 2})
])
def test_comms_api_config_default_values(init_values, expected):
    """Check the correct initialization of the `CommsAPIConfig` class."""
    config = CommsAPIConfig(**init_values)

    assert config.host == expected["host"]
    assert config.port == expected["port"]
    assert config.workers == expected["workers"]


@pytest.mark.parametrize("values", [
    {"port": 0},
    {"port": -2},
    {"workers": 0},
    {"workers": -2}
])
def test_comms_api_config_invalid_values(values):
    """Check the correct behavior of the `CommsAPIConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = CommsAPIConfig(**values)
