# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import datetime
import logging
import os
import signal
from typing import Dict, Tuple, Any, List

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jsonschema import validate, ValidationError

import wazuh.core.utils as core_utils
from api.api_exception import APIError
from api.constants import CONFIG_FILE_PATH, SECURITY_CONFIG_PATH, API_SSL_PATH
from api.validator import api_config_schema, security_config_schema

CACHE_DEPRECATED_MESSAGE = 'The `cache` API configuration option was deprecated in {release} and will be removed ' \
                           'in the next minor release.'

default_security_configuration = {
    "auth_token_exp_timeout": 900,
    "rbac_mode": "white"
}

default_api_configuration = {
    "host": ["0.0.0.0", "::"],
    "port": 55000,
    "drop_privileges": True,
    "experimental_features": False,
    "max_upload_size": 10485760,
    "authentication_pool_size": 2,
    "intervals": {
        "request_timeout": 10
    },
    "https": {
        "enabled": True,
        "key": "server.key",
        "cert": "server.crt",
        "use_ca": False,
        "ca": "ca.crt",
        "ssl_protocol": "auto",
        "ssl_ciphers": ""
    },
    "logs": {
        "level": "info",
        "format": "plain",
        "max_size": {
            "enabled": False,
            "size": "1M"
        }
    },
    "cors": {
        "enabled": False,
        "source_route": "*",
        "expose_headers": "*",
        "allow_headers": "*",
        "allow_credentials": False,
    },
    "access": {
        "max_login_attempts": 50,
        "block_time": 300,
        "max_request_per_minute": 300
    },
    "upload_configuration": {
        "remote_commands": {
            "localfile": {
                "allow": True,
                "exceptions": []
            },
            "wodle_command": {
                "allow": True,
                "exceptions": []
            }
        },
        "limits": {
            "eps": {
                "allow": True
            }
        },
        "agents": {
            "allow_higher_versions": {
                "allow": True
            }
        },
        "indexer": {
            "allow": True
        },
        "integrations": {
            "virustotal": {
                "public_key": {
                    "allow": True,
                    "minimum_quota": 240
                }
            }
        }
    }
}


def dict_to_lowercase(mydict: Dict):
    """Turn all string values of a dictionary to lowercase. Also support nested dictionaries.

    Parameters
    ----------
    mydict : dict
        Dictionary with the values we want to convert.
    """
    for k, val in filter(lambda x: isinstance(x[1], str) or isinstance(x[1], dict), mydict.items()):
        if isinstance(val, dict):
            dict_to_lowercase(mydict[k])
        else:
            mydict[k] = val.lower()


def append_wazuh_prefixes(dictionary: Dict, path_fields: Dict[Any, List[Tuple[str, str]]]) -> None:
    """Append Wazuh prefix to all path fields in a dictionary.
    Parameters
    ----------
    dictionary : dict
        Dictionary with the API configuration.
    path_fields : dict
        Key: Prefix to append (path)
        Values: Sections of the configuration to append the prefix to.
    """
    for prefix, configurations in path_fields.items():
        for config in configurations:
            try:
                section, subsection = config
                dictionary[section][subsection] = os.path.join(prefix, dictionary[section][subsection])
            except KeyError:
                pass


def fill_dict(default: Dict, config: Dict, json_schema: Dict) -> Dict:
    """Validate and fill a dictionary's missing values using default ones.

    Parameters
    ----------
    default : dict
        Dictionary with default values.
    config : dict
        Dictionary to be filled.
    json_schema : dict
        Jsonschema with allowed properties.

    Returns
    -------
    dict
        Filled dictionary.
    """
    def _update_default_config(default_config: Dict, user_config: Dict) -> Dict:
        """Update default configuration with the values of the user one.

        Parameters
        ----------
        default_config : dict
            Default API configuration.
        user_config : dict
            User API configuration.

        Returns
        -------
        dict
            Merged API configuration.
        """
        for key, value in user_config.items():
            if isinstance(value, dict):
                default_config[key] = _update_default_config(default_config.get(key, {}), value)
            else:
                default_config[key] = value
        return default_config

    try:
        validate(instance=config, schema=json_schema)
    except ValidationError as validation_exc:
        raise APIError(2000, details=validation_exc.message) from None

    return _update_default_config(default, config)


def generate_private_key(private_key_path: str, public_exponent: int = 65537,
                         key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate a private key in 'CONFIG_PATH/ssl/server.key'.

    Parameters
    ----------
    private_key_path : str
        Path where the private key will be generated.
    public_exponent : int, optional
        Key public exponent. Default `65537`
    key_size : int, optional
        Key size. Default `2048`

    Returns
    -------
    rsa.RSAPrivateKey
        Private key.
    """
    key = rsa.generate_private_key(
        public_exponent,
        key_size,
        crypto_default_backend()
    )
    with open(private_key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(private_key_path, 0o400)

    return key


def generate_self_signed_certificate(private_key: rsa.RSAPrivateKey, certificate_path: str):
    """Generate a self-signed certificate using a generated private key. The certificate will be created in
    'CONFIG_PATH/ssl/server.crt'.

    Parameters
    ----------
    private_key : RSAPrivateKey
        Private key.
    certificate_path : str
        Path where the self-signed certificate will be generated.
    """
    # Generate private key
    # Various details about who we are. For a self-signed certificate, the subject and issuer are always the same
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Wazuh"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"wazuh.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for one year
        core_utils.get_utc_now() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(private_key, hashes.SHA256(), crypto_default_backend())
    # Write our certificate out to disk.
    with open(certificate_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(certificate_path, 0o400)


def read_yaml_config(config_file: str = CONFIG_FILE_PATH, default_conf: dict = None) -> Dict:
    """Read user API configuration and merge it with the default one.

    Parameters
    ----------
    config_file : str
        Configuration file path.
    default_conf : dict
        Default configuration to be merged with the user's one.

    Returns
    -------
    dict
        API configuration.
    """

    def replace_bools(conf: dict):
        """Replace 'yes' and 'no' strings in configuration for actual booleans.

        Parameters
        ----------
        conf : dict
            Current API configuration.
        """
        for k in conf.keys():
            if isinstance(conf[k], dict):
                replace_bools(conf[k])
            else:
                if isinstance(conf[k], str):
                    if conf[k].lower() == 'yes':
                        conf[k] = True
                    elif conf[k].lower() == 'no':
                        conf[k] = False

    if default_conf is None:
        default_conf = default_api_configuration

    if config_file and os.path.exists(config_file):
        try:
            with open(config_file) as f:
                configuration = yaml.safe_load(f)
            # Replace strings for booleans
            configuration and replace_bools(configuration)
        except IOError as e:
            raise APIError(2004, details=e.strerror) from None
    else:
        configuration = None

    if configuration is None:
        configuration = copy.deepcopy(default_conf)
    else:
        # If any value is missing from user's configuration, add the default one:
        dict_to_lowercase(configuration)

        # Check if cache is enabled
        if configuration.get('cache', {}).get('enabled', {}):
            logger = logging.getLogger('wazuh-api')
            logger.warning(CACHE_DEPRECATED_MESSAGE.format(release="4.8.0"))

        schema = security_config_schema if config_file == SECURITY_CONFIG_PATH else api_config_schema
        configuration = fill_dict(default_conf, configuration, schema)

    # Append Wazuh prefixes to all relative paths in configuration
    append_wazuh_prefixes(configuration, {API_SSL_PATH: [('https', 'key'), ('https', 'cert'), ('https', 'ca')]})

    return configuration


def init_auth_worker():
    """Set authentication pool worker to ignore SIGINT signals to avoid 
    throwing exceptions when shutting down the API in foreground mode."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# Check if the default configuration is valid according to its jsonschema, so we are forced to update the schema if any
# change is performed to the configuration.
try:
    validate(instance=default_security_configuration, schema=security_config_schema)
    validate(instance=default_api_configuration, schema=api_config_schema)
except ValidationError as e:
    raise APIError(2000, details=e.message) from None

# Configuration - global object
api_conf = read_yaml_config()
security_conf = read_yaml_config(config_file=SECURITY_CONFIG_PATH, default_conf=default_security_configuration)
