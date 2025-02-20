# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os

import wazuh.core.utils as core_utils
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CACHE_DEPRECATED_MESSAGE = (
    'The `cache` API configuration option was deprecated in {release} and will be removed in the next minor release.'
)

default_security_configuration = {'auth_token_exp_timeout': 900, 'rbac_mode': 'white'}


def generate_private_key(private_key_path: str) -> ec.EllipticCurvePrivateKey:
    """Generate a private key in 'CERTS_PATH/api.key'.

    Parameters
    ----------
    private_key_path : str
        Path where the private key will be generated.

    Returns
    -------
    ec.EllipticCurvePrivateKey
        Private key.
    """
    key = ec.generate_private_key(curve=ec.SECP256K1(), backend=crypto_default_backend())
    with open(private_key_path, 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(private_key_path, 0o400)

    return key


def generate_self_signed_certificate(private_key: ec.EllipticCurvePrivateKey, certificate_path: str):
    """Generate a self-signed certificate using a generated private key. The certificate will be created in
    'CERTS_PATH/api.crt'.

    Parameters
    ----------
    private_key : EllipticCurvePrivateKey
        Private key.
    certificate_path : str
        Path where the self-signed certificate will be generated.
    """
    # Generate private key
    # Various details about who we are. For a self-signed certificate, the subject and issuer are always the same
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Wazuh'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'wazuh.com'),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc))
        .not_valid_after(
            # Our certificate will be valid for one year
            core_utils.get_utc_now() + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(private_key, hashes.SHA256(), crypto_default_backend())
    )
    # Write our certificate out to disk.
    with open(certificate_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(certificate_path, 0o400)
