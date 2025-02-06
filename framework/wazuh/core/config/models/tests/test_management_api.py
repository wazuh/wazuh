import pytest
from pydantic import ValidationError
from wazuh.core.config.models.management_api import (
    AccessConfig,
    CorsConfig,
    ManagementAPIConfig,
    ManagementAPIIntervals,
)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'request_timeout': 10}),
    ({'request_timeout': 3}, {'request_timeout': 3})
])
def test_management_api_intervals_default_values(init_values, expected):
    """Check the correct initialization of the `ManagementAPIIntervals` class."""
    config = ManagementAPIIntervals(**init_values)

    assert config.request_timeout == expected['request_timeout']


@pytest.mark.parametrize('value', [
    -10,
    0
])
def test_management_api_intervals_invalid_values(value):
    """Check the correct behavior of the `ManagementAPIIntervals` class validations."""
    with pytest.raises(ValidationError):
        _ = ManagementAPIIntervals(request_timeout=value)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'enabled': False, 'source_route': '*', 'expose_headers': '*', 'allow_headers': '*', 'allow_credentials': False}),
    ({'enabled': True, 'source_route': 'some_value', 'expose_headers': 'some_value', 'allow_headers': 'some_value', 'allow_credentials': True},
     {'enabled': True, 'source_route': 'some_value', 'expose_headers': 'some_value', 'allow_headers': 'some_value', 'allow_credentials': True})
])
def test_cors_config_default_values(init_values, expected):
    """Check the correct initialization of the `CorsConfig` class."""
    config = CorsConfig(**init_values)

    assert config.enabled == expected['enabled']
    assert config.source_route == expected['expose_headers']
    assert config.allow_headers == expected['allow_headers']
    assert config.allow_credentials == expected['allow_credentials']
    assert config.expose_headers == expected['expose_headers']


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'max_login_attempts': 50, 'block_time': 300, 'max_request_per_minute': 300}),
    ({'max_login_attempts': 5, 'block_time': 30, 'max_request_per_minute': 30},
     {'max_login_attempts': 5, 'block_time': 30, 'max_request_per_minute': 30})
])
def test_access_config_default_values(init_values, expected):
    """Check the correct initialization of the `AccessConfig` class."""
    config = AccessConfig(**init_values)

    assert config.max_login_attempts == expected['max_login_attempts']
    assert config.block_time == expected['block_time']
    assert config.max_request_per_minute == expected['max_request_per_minute']


@pytest.mark.parametrize('values', [
    {'max_login_attempts': 0},
    {'max_login_attempts': -2},
    {'block_time': -4},
    {'block_time': 0},
    {'max_request_per_minute': -3},
    {'max_request_per_minute': 0}
])
def test_access_config_invalid_values(values):
    """Check the correct behavior of the `AccessConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = AccessConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {
        'host': ['localhost', '::1'],
        'port': 55000,
        'drop_privileges': True,
        'max_upload_size': 10485760,
        'jwt_expiration_timeout': 900,
        'rbac_mode': 'white',
        'intervals': {},
        'cors': {},
        'access': {}
    }),
    ({
        'host': ['example', '::'],
        'port': 55050,
        'drop_privileges': False,
        'max_upload_size': 101,
        'jwt_expiration_timeout': 4,
        'rbac_mode': 'black',
        'intervals': {'request_timeout': 10},
        'cors': {'enabled': True},
        'access': {'max_login_attempts': 4}
    }, {
        'host': ['example', '::'],
        'port': 55050,
        'drop_privileges': False,
        'max_upload_size': 101,
        'jwt_expiration_timeout': 4,
        'rbac_mode': 'black',
        'intervals': {'request_timeout': 10},
        'cors': {'enabled': True},
        'access': {'max_login_attempts': 4}
    })
])
def test_management_api_config_default_values(init_values, expected):
    """Check the correct initialization of the `ManagementAPIConfig` class."""
    config = ManagementAPIConfig(**init_values)

    assert config.host == expected['host']
    assert config.port == expected['port']
    assert config.drop_privileges == expected['drop_privileges']
    assert config.max_upload_size == expected['max_upload_size']
    assert config.jwt_expiration_timeout == expected['jwt_expiration_timeout']
    assert config.rbac_mode == expected['rbac_mode']
    assert config.intervals == ManagementAPIIntervals(**expected['intervals'])
    assert config.cors == CorsConfig(**expected['cors'])
    assert config.access == AccessConfig(**expected['access'])


@pytest.mark.parametrize('values', [
    {'host': ['localhost']},
    {'host': []},
    {'port': -200},
    {'port': 0},
    {'drop_privileges': ''},
    {'max_upload_size': 0},
    {'max_upload_size': -10},
    {'jwt_expiration_timeout': -25},
    {'jwt_expiration_timeout': 0},
    {'rbac_mode': 'green'}
])
def test_management_api_invalid_values(values):
    """Check the correct behavior of the `ManagementAPIConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = ManagementAPIConfig(**values)
