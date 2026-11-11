# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from connexion.exceptions import ProblemException
from api.constants import CONFIG_FILE_PATH
from wazuh.core.exception import DOCU_VERSION, WazuhTooManyRequests


class APIException(Exception):
    """
    Wazuh API exception class.
    """

    def __init__(self, code: int, details: str = None, config_file: str = None):
        """APIException class constructor.

        Parameters
        ----------
        code : int
            Error code.
        details : str
            Extra details to add to the default exception message to include useful context information.
        config_file : str
            Configuration file the error is about. Default: the API configuration file.
        """
        self.code = code
        self.details = details
        self.config_file = config_file if config_file is not None else CONFIG_FILE_PATH
        self.exceptions = {
            2000: 'Some parameters are not expected in the configuration file '
                  f"({self.config_file}). Please check the documentation for further details: "
                  f"https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/configuration.html"
                  '#api-configuration-options',
            2003: 'Error loading SSL/TLS certificates',
            2004: 'Configuration file could not be loaded',
            2010: 'Error while attempting to bind on address: address already in use',
            2011: 'Error setting up API logger',
            2012: 'Error while attempting to check RBAC database integrity'
        }

    def __str__(self) -> str:
        """Magic method str().

        Returns
        -------
        str
            String representation of the APIException object.
        """
        details = '.' if self.details is None else f': {self.details}.'
        return f"{self.code} - {self.exceptions[self.code]}{details}"


class APIError(APIException):
    pass


class BlockedIPException(ProblemException):
    """Bocked IP Exception Class."""
    def __init__(self, *, status=500, title=None, detail=None):
        ext = {"code": 6000}
        super().__init__(status=status, title=title, detail=detail, ext=ext)


class MaxRequestsException(ProblemException):
    """Bocked IP Exception Class."""
    def __init__(self, code):
        exc = WazuhTooManyRequests(code=code)
        ext = {"code": exc.code}
        ext.update({"remediation": exc.remediation} if hasattr(exc, 'remediation') else {})
        super().__init__(status=429, title=exc.title, detail=exc.message, type=exc.type, ext=ext)


class ExpectFailedException(ProblemException):
    """Exception for failed expectation (status code 417)."""

    def __init__(self, *, status=417, title=None, detail=None):
        ext = {"code": 417}
        super().__init__(status=status, title=title, detail=detail, ext=ext)


class PayloadTooLargeException(ProblemException):
    """Exception for request bodies that exceed the maximum allowed size (status code 413)."""

    def __init__(self, *, title=None, detail=None):
        ext = {"code": 413}
        super().__init__(status=413, title=title, detail=detail, ext=ext)
