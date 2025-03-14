import logging

import pytest
from pydantic import ValidationError
from wazuh.core.config.models.logging import (
    APILoggingConfig,
    APILoggingLevel,
    EngineLoggingConfig,
    EngineLoggingLevel,
    LoggingConfig,
    LoggingLevel,
)


@pytest.mark.parametrize(
    'init_values, expected', [({}, EngineLoggingLevel.info), ({'level': 'trace'}, EngineLoggingLevel.trace)]
)
def test_engine_logging_config_default_values(init_values, expected):
    """Check the correct initialization of the `EngineLoggingConfig` class."""
    config = EngineLoggingConfig(**init_values)

    assert config.level == expected


@pytest.mark.parametrize('value', ['info1', ''])
def test_logging_config_invalid_values(value):
    """Check the correct behavior of the `EngineLoggingConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = EngineLoggingConfig(**{'level': value})


@pytest.mark.parametrize('init_values, expected', [({}, LoggingLevel.info), ({'level': 'debug'}, LoggingLevel.debug)])
def test_logging_config_default_values(init_values, expected):
    """Check the correct initialization of the `LoggingConfig` class."""
    config = LoggingConfig(**init_values)

    assert config.level == expected


@pytest.mark.parametrize('value, expected', [(LoggingLevel.info, 0), (LoggingLevel.debug, 1), (LoggingLevel.debug2, 2)])
def test_get_level_values(value, expected):
    """Check the correct behavior of the `get_level_value` method."""
    config = LoggingConfig(level=value)

    assert config.get_level_value() == expected


@pytest.mark.parametrize('init_values', [{'level': 'invalid'}, {'format': ['non']}, {'format': []}])
def test_api_logging_config_invalid_values(init_values):
    """Check the correct behavior of the `APILoggingConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = APILoggingConfig(**init_values)


@pytest.mark.parametrize(
    'value, expected',
    [
        (APILoggingLevel.debug, logging.DEBUG),
        (APILoggingLevel.info, logging.INFO),
        (APILoggingLevel.warning, logging.WARNING),
        (APILoggingLevel.error, logging.ERROR),
        (APILoggingLevel.critical, logging.CRITICAL),
    ],
)
def test_get_level(value, expected):
    """Check the correct behavior of the `get_level` method."""
    config = APILoggingConfig(level=value)

    assert config.get_level() == expected
