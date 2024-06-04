"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest

from wazuh_testing.tools.certificate_controller import CertificateController


@pytest.fixture()
def generate_ca_certificate(test_metadata):
    """
    Generate custom CA certificate.
    """
    SSL_AGENT_CA = '/var/ossec/etc/test_rootCA.pem'
    SSL_AGENT_CERT = '/tmp/test_sslagent.cert'
    SSL_AGENT_PRIVATE_KEY = '/tmp/test_sslagent.key'
    AGENT_IP = '127.0.0.1'
    WRONG_IP = '10.0.0.240'
    # Generate root key and certificate
    controller = CertificateController()
    option = test_metadata['sim_option']
    if option not in ['NO_CERT']:
        # Wheter manager will recognize or not this key
        will_sign = True if option in ['VALID CERT', 'INCORRECT HOST'] else False
        controller.generate_agent_certificates(SSL_AGENT_PRIVATE_KEY, SSL_AGENT_CERT,
                                               WRONG_IP if option == 'INCORRECT HOST' else AGENT_IP, signed=will_sign)
    controller.store_ca_certificate(controller.get_root_ca_cert(), SSL_AGENT_CA)
