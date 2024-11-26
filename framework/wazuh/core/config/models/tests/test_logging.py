import logging

import pytest
from pydantic import ValidationError

from wazuh.core.config.models.logging import LoggingFormat, LoggingLevel, LoggingConfig, \
    APILoggingLevel, LogFileMaxSizeConfig, RotatedLoggingConfig, EngineLoggingLevel, EngineLoggingConfig


@pytest.mark.parametrize('init_values, expected', [
    ({}, EngineLoggingLevel.info),
    ({'level': 'trace'}, EngineLoggingLevel.trace)
])
def test_engine_logging_config_default_values(init_values, expected):
    """Check the correct initialization of the `EngineLoggingConfig` class."""
    config = EngineLoggingConfig(**init_values)

    assert config.level == expected


@pytest.mark.parametrize('value', [
    'info1',
    ''
])
def test_logging_config_invalid_values(value):
    """Check the correct behavior of the `EngineLoggingConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = EngineLoggingConfig(**{'level': value})


@pytest.mark.parametrize('init_values, expected', [
    ({}, LoggingLevel.info),
    ({'level': 'debug'}, LoggingLevel.debug)
])
def test_logging_config_default_values(init_values, expected):
    """Check the correct initialization of the `LoggingConfig` class."""
    config = LoggingConfig(**init_values)

    assert config.level == expected


@pytest.mark.parametrize('value', [
    'info1',
    ''
])
def test_logging_config_invalid_values(value):
    """Check the correct behavior of the `LoggingConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = LoggingConfig(**{'level': value})


@pytest.mark.parametrize('value, expected', [
    (LoggingLevel.info, 0),
    (LoggingLevel.debug, 1),
    (LoggingLevel.debug2, 2)
])
def test_get_level_values(value, expected):
    """Check the correct behavior of the `get_level_value` method."""
    config = LoggingConfig(level=value)

    assert config.get_level_value() == expected


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'enabled': False, 'size': '1M'}),
    ({'enabled': True, 'size': '20K'}, {'enabled': True, 'size': '20K'})
])
def test_log_file_max_size_config_default_values(init_values, expected):
    """Check the correct initialization of the `LogFileMaxSizeConfig` class."""
    config = LogFileMaxSizeConfig(**init_values)

    assert config.size == expected['size']
    assert config.enabled == expected['enabled']


@pytest.mark.parametrize('value', [
    '',
    '1MK',
    '1',
    '-1M',
    '0K',
])
def test_log_file_max_size_config_invalid_values(value):
    """Check the correct behavior of the `LogFileMaxSizeConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = LogFileMaxSizeConfig(size=value)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'level': APILoggingLevel.debug, 'format': [LoggingFormat.plain], 'max_size': {}}),
    ({'level': APILoggingLevel.info, 'format': [LoggingFormat.plain, LoggingFormat.json], 'max_size': {'size': '3M'}},
     {'level': APILoggingLevel.info, 'format': [LoggingFormat.plain, LoggingFormat.json], 'max_size': {'size': '3M'}})
])
def test_rotated_logging_config_default_values(init_values, expected):
    """Check the correct initialization of the `RotatedLoggingConfig` class."""
    config = RotatedLoggingConfig(**init_values)

    assert config.level == expected['level']
    assert config.format == expected['format']
    assert config.max_size == LogFileMaxSizeConfig(**expected['max_size'])


@pytest.mark.parametrize('init_values', [
    {'level': 'invalid'},
    {'format': ['non']},
    {'format': []}

])
def test_rotated_logging_config_invalid_values(init_values):
    """Check the correct behavior of the `RotatedLoggingConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = RotatedLoggingConfig(**init_values)


@pytest.mark.parametrize('value, expected', [
    (APILoggingLevel.debug, logging.DEBUG),
    (APILoggingLevel.info, logging.INFO),
    (APILoggingLevel.warning, logging.WARNING),
    (APILoggingLevel.error, logging.ERROR),
    (APILoggingLevel.critical, logging.CRITICAL)
])
def test_get_level(value, expected):
    """Check the correct behavior of the `get_level` method."""
    config = RotatedLoggingConfig(level=value)

    assert config.get_level() == expected
