# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import datetime
import os
from typing import Dict, List, Tuple

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from api.api_exception import APIError
from api.constants import SECURITY_CONFIG_PATH
from wazuh.core import common

default_security_configuration = {
    "auth_token_exp_timeout": 3600,
    "rbac_mode": "white"
}

default_api_configuration = {
    "host": "0.0.0.0",
    "port": 55000,
    "behind_proxy_server": False,
    "https": {
        "enabled": True,
        "key": "api/configuration/ssl/server.key",
        "cert": "api/configuration/ssl/server.crt",
        "use_ca": False,
        "ca": "api/configuration/ssl/ca.crt"
    },
    "logs": {
        "level": "info",
        "path": "logs/api.log"
    },
    "cors": {
        "enabled": False,
        "source_route": "*",
        "expose_headers": "*",
        "allow_headers": "*",
        "allow_credentials": False,
    },
    "cache": {
        "enabled": True,
        "time": 0.750
    },
    "access": {
        "max_login_attempts": 50,
        "block_time": 300,
        "max_request_per_minute": 300
    },
    "use_only_authd": False,
    "drop_privileges": True,
    "experimental_features": False,
    "remote_commands": {
        "localfile": {
            "enabled": True,
            "exceptions": ["df -P",
                           "netstat -tan |grep LISTEN |grep -v 127.0.0.1 | sort",
                           "last -n 5",
                           ]
        },
        "wodle_command": {
            "enabled": True,
            "exceptions": []
        }
    }
}


def dict_to_lowercase(mydict: Dict):
    """Turns all str values to lowercase. Supports nested dictionaries.

    :param mydict: Dictionary to lowercase
    :return: None (the dictionary's reference is modified)
    """
    for k, val in filter(lambda x: isinstance(x[1], str) or isinstance(x[1], dict), mydict.items()):
        if isinstance(val, dict):
            dict_to_lowercase(mydict[k])
        else:
            mydict[k] = val.lower()


def append_ossec_path(dictionary: Dict, path_fields: List[Tuple[str, str]]):
    """Appends ossec path to all path fields in a dictionary

    :param dictionary: dictionary to append ossec path
    :param path_fields: List of tuples containing path fields
    :return: None (the dictionary's reference is modified)
    """
    for section, subsection in path_fields:
        try:
            dictionary[section][subsection] = os.path.join(common.ossec_path, dictionary[section][subsection])
        except KeyError:
            pass


def fill_dict(default: Dict, config: Dict) -> Dict:
    """Fills a dictionary's missing values using default ones.

    :param default: Dictionary with default values
    :param config: Dictionary to fill
    :return: Filled dictionary
    """
    # Check there aren't extra configuration values in user's configuration:
    for k in config.keys():
        if k not in default.keys():
            raise APIError(2000, details=', '.join(config.keys() - default.keys()))

    for k, val in filter(lambda x: isinstance(x[1], dict), config.items()):
        for item, value in config[k].items():
            config[k][item] = default[k][item] if value == "" else config[k][item]
        config[k] = {**default[k], **config[k]}

    return {**default, **config}


def generate_private_key(private_key_path, public_exponent=65537, key_size=2048):
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
    RSAPrivateKey
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


def generate_self_signed_certificate(private_key, certificate_path):
    """Generate a self signed certificate using a generated private key. The certificate will be created in
        'CONFIG_PATH/ssl/server.crt'.

    Parameters
    ----------
    private_key : RSAPrivateKey
        Private key.
    certificate_path : str
        Path where the self signed certificate will be generated.
    """
    # Generate private key
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(private_key, hashes.SHA256(), crypto_default_backend())
    # Write our certificate out to disk.
    with open(certificate_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(certificate_path, 0o400)


def read_yaml_config(config_file=common.api_config_path, default_conf=None) -> Dict:
    """Reads user API configuration and merges it with the default one

    :return: API configuration
    """
    if default_conf is None:
        default_conf = default_api_configuration

    if os.path.exists(config_file):
        try:
            with open(config_file) as f:
                configuration = yaml.safe_load(f)
        except IOError as e:
            raise APIError(2004, details=e.strerror)
    else:
        configuration = None

    # If any value is missing from user's cluster configuration, add the default one:
    if configuration is None:
        configuration = copy.deepcopy(default_conf)
    else:
        dict_to_lowercase(configuration)
        configuration = fill_dict(default_conf, configuration)

    # Append ossec_path to all paths in configuration
    append_ossec_path(configuration, [('logs', 'path'), ('https', 'key'), ('https', 'cert'), ('https', 'ca')])

    return configuration


# Configuration - global object
api_conf = dict()
security_conf = read_yaml_config(config_file=SECURITY_CONFIG_PATH, default_conf=default_security_configuration)
