# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from api.models.base_model_ import Body


class EnrollmentTokenCreateModel(Body):
    """Body of POST /agents/enrollment-tokens (issue #38993): what `wazuh-manager-authd
    --create-enrollment-token` takes on the command line, as JSON."""

    def __init__(self, address=None, port=None, prefix=None, ttl=None, max_uses=None, description=None,
                 embed_ca=None, no_credential=None):
        """EnrollmentTokenCreateModel body model
        :param address: Name (or IP) the agents connect to. Must be one of the names in the listener certificate.
        :type address: str
        :param port: Listener port to write into the token when it differs from the configured one.
        :type port: int
        :param prefix: URL prefix to write into the token when it differs from the configured one.
        :type prefix: str
        :param ttl: Lifetime as a timeframe (30d, 12h, 45m, 90s). authd's default (30 days) when omitted.
        :type ttl: str
        :param max_uses: Enrollments the token allows. 0 or omitted means unlimited.
        :type max_uses: int
        :param description: Free text shown when listing.
        :type description: str
        :param embed_ca: Carry the CA certificate instead of its pin.
        :type embed_ca: bool
        :param no_credential: Token without credential: address and pin only.
        :type no_credential: bool
        """
        self.swagger_types = {
            'address': str,
            'port': int,
            'prefix': str,
            'ttl': str,
            'max_uses': int,
            'description': str,
            'embed_ca': bool,
            'no_credential': bool
        }

        self.attribute_map = {
            'address': 'address',
            'port': 'port',
            'prefix': 'prefix',
            'ttl': 'ttl',
            'max_uses': 'max_uses',
            'description': 'description',
            'embed_ca': 'embed_ca',
            'no_credential': 'no_credential'
        }

        self._address = address
        self._port = port
        self._prefix = prefix
        self._ttl = ttl
        self._max_uses = max_uses
        self._description = description
        self._embed_ca = embed_ca
        self._no_credential = no_credential

    @property
    def address(self) -> str:
        return self._address

    @address.setter
    def address(self, address):
        self._address = address

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, port):
        self._port = port

    @property
    def prefix(self) -> str:
        return self._prefix

    @prefix.setter
    def prefix(self, prefix):
        self._prefix = prefix

    @property
    def ttl(self) -> str:
        return self._ttl

    @ttl.setter
    def ttl(self, ttl):
        self._ttl = ttl

    @property
    def max_uses(self) -> int:
        return self._max_uses

    @max_uses.setter
    def max_uses(self, max_uses):
        self._max_uses = max_uses

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def embed_ca(self) -> bool:
        return self._embed_ca

    @embed_ca.setter
    def embed_ca(self, embed_ca):
        self._embed_ca = embed_ca

    @property
    def no_credential(self) -> bool:
        return self._no_credential

    @no_credential.setter
    def no_credential(self, no_credential):
        self._no_credential = no_credential
