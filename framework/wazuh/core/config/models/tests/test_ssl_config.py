from unittest.mock import call, patch

import pytest
from pydantic import ValidationError
from wazuh.core.common import WAZUH_INDEXER_CA_BUNDLE
from wazuh.core.config.models.ssl_config import APISSLConfig, IndexerSSLConfig, SSLConfig, SSLProtocol
from wazuh.core.exception import WazuhError


@pytest.mark.parametrize(
    'init_values,expected',
    [
        ({'key': 'key_example', 'cert': 'cert_example', 'ca': 'ca_example'}, ''),
        ({'key': 'key_example', 'cert': 'cert_example', 'ca': 'ca_example', 'keyfile_password': 'example'}, 'example'),
    ],
)
@patch('os.path.isfile', return_value=True)
def test_ssl_config_default_values(file_exists_mock, init_values, expected):
    """Check the correct initialization of the `SSLConfig` class."""
    ssl_config = SSLConfig(**init_values)

    assert ssl_config.keyfile_password == expected


@pytest.mark.parametrize(
    'init_values',
    [
        {},
        {'key': 'key_example'},
        {'key': 'key_example', 'cert': 'cert_example'},
    ],
)
def test_ssl_config_fails_without_values(init_values):
    """Check the correct behavior of the `SSLConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = SSLConfig(**init_values)


@pytest.mark.parametrize(
    'init_values,expected',
    [
        (
            {
                'use_ssl': True,
                'key': 'key_example',
                'certificate': 'cert_example',
                'certificate_authorities': ['ca_example'],
                'verify_certificates': False,
            },
            {
                'use_ssl': True,
                'key': 'key_example',
                'certificate': 'cert_example',
                'certificate_authorities': ['ca_example'],
                'verify_certificates': False,
            },
        ),
        (
            {
                'use_ssl': True,
                'key': 'key_example',
                'certificate': 'cert_example',
                'certificate_authorities': ['ca_example'],
                'verify_certificates': True,
            },
            {
                'use_ssl': True,
                'key': 'key_example',
                'certificate': 'cert_example',
                'certificate_authorities': ['ca_example'],
                'verify_certificates': True,
            },
        ),
    ],
)
@patch('os.path.isfile', return_value=True)
@patch('builtins.open')
@patch('wazuh.core.config.models.ssl_config.assign_wazuh_ownership')
def test_indexer_ssl_config_default_values(assign_ownership_mock, open_mock, file_exists_mock, init_values, expected):
    """Check the correct initialization of the `IndexerSSLConfig` class."""
    ssl_config = IndexerSSLConfig(**init_values)

    assert ssl_config.use_ssl == expected['use_ssl']
    assert ssl_config.key == expected['key']
    assert ssl_config.certificate == expected['certificate']
    assert ssl_config.certificate_authorities == expected['certificate_authorities']
    assert ssl_config.verify_certificates == expected['verify_certificates']


@patch('os.path.isfile', return_value=True)
@patch('builtins.open')
@patch('wazuh.core.config.models.ssl_config.assign_wazuh_ownership')
def test_indexer_ssl_config_create_bundle_file(assign_ownership_mock, open_mock, file_exists_mock):
    """Validate that the CA bundle file is created during the indexer SSL configuration class construction."""
    ssl_config = IndexerSSLConfig(use_ssl=True, certificate_authorities=['root_ca.pem', 'intermediate.pem'])

    open_mock.assert_has_calls(
        [
            call(WAZUH_INDEXER_CA_BUNDLE, 'w'),
            call('root_ca.pem', 'r'),
            call('intermediate.pem', 'r'),
        ],
        any_order=True,
    )
    assign_ownership_mock.assert_called_once_with(WAZUH_INDEXER_CA_BUNDLE)
    assert ssl_config.certificate_authorities_bundle == WAZUH_INDEXER_CA_BUNDLE


@patch('os.path.isfile', return_value=True)
@patch('builtins.open', side_effect=IOError)
def test_indexer_ssl_config_create_bundle_file_ko(open_mock, file_exists_mock):
    """Validate that any errors during the CA bundle file creation are handled successfully."""
    with pytest.raises(WazuhError, match=r'1006'):
        IndexerSSLConfig(use_ssl=True, certificate_authorities=['root_ca.pem', 'intermediate.pem'])


@pytest.mark.parametrize(
    'init_values,expected',
    [
        (
            {'key': 'key_example', 'cert': 'cert_example'},
            {'use_ca': False, 'ca': '', 'ssl_protocol': SSLProtocol.auto, 'ssl_ciphers': ''},
        ),
        (
            {'key': 'key_example', 'cert': 'cert_example', 'use_ca': True},
            {'use_ca': True, 'ca': '', 'ssl_protocol': SSLProtocol.auto, 'ssl_ciphers': ''},
        ),
        (
            {'key': 'key_example', 'cert': 'cert_example', 'use_ca': True, 'ca': 'ca_example'},
            {'use_ca': True, 'ca': 'ca_example', 'ssl_protocol': SSLProtocol.auto, 'ssl_ciphers': ''},
        ),
        (
            {
                'key': 'key_example',
                'cert': 'cert_example',
                'use_ca': True,
                'ca': 'ca_example',
                'ssl_protocol': SSLProtocol.tls,
            },
            {'use_ca': True, 'ca': 'ca_example', 'ssl_protocol': SSLProtocol.tls, 'ssl_ciphers': ''},
        ),
        (
            {
                'key': 'key_example',
                'cert': 'cert_example',
                'use_ca': True,
                'ca': 'ca_example',
                'ssl_protocol': SSLProtocol.tls,
                'ssl_ciphers': 'cipher_example',
            },
            {'use_ca': True, 'ca': 'ca_example', 'ssl_protocol': SSLProtocol.tls, 'ssl_ciphers': 'cipher_example'},
        ),
    ],
)
@patch('os.path.isfile', return_value=True)
def test_api_ssl_config_default_values(isfile_mock, init_values, expected):
    """Check the correct initialization of the `APISSLConfig` class."""
    ssl_config = APISSLConfig(**init_values)

    assert ssl_config.use_ca == expected['use_ca']
    assert ssl_config.ca == expected['ca']
    assert ssl_config.ssl_protocol == expected['ssl_protocol']
    assert ssl_config.ssl_ciphers == expected['ssl_ciphers']


@pytest.mark.parametrize('init_values', [{}, {'key': 'key_example'}, {'cert': 'cert_example'}])
def test_api_ssl_config_fails_without_values(init_values):
    """Check the correct behavior of the `APISSLConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = APISSLConfig(**init_values)
