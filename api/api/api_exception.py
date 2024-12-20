# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from connexion.exceptions import ProblemException
from wazuh.core.exception import WazuhTooManyRequests


class APIException(Exception):
    """Wazuh API exception class."""

    def __init__(self, code: int, details: str = None):
        """APIException class constructor.

        Parameters
        ----------
        code : int
            Error code.
        details : str
            Extra details to add to the default exception message to include useful context information.
        """
        self.code = code
        self.details = details
        # show relative paths in exceptions
        self.exceptions = {
            2000: 'Some parameters are not expected in the configuration',
            2002: 'Error migrating configuration from old API version. ' 'Default configuration will be applied',
            2003: 'Error loading SSL/TLS certificates',
            2004: 'Configuration file could not be loaded',
            2005: 'Body request is not a valid JSON',
            2006: 'Error parsing body request to UTF-8',
            2007: 'Body is empty',
            2009: 'Semicolon (;) is a reserved character and must ' 'be percent-encoded (%3B) to use it.',
            2010: 'Error while attempting to bind on address: address already in use',
            2011: 'Error setting up API logger',
            2012: 'Error while attempting to check RBAC database integrity',
        }

    def __str__(self) -> str:
        """Magic method str().

        Returns
        -------
        str
            String representation of the APIException object.
        """
        details = '.' if self.details is None else f': {self.details}.'
        return f'{self.code} - {self.exceptions[self.code]}{details}'


class APIError(APIException):
    pass


class BlockedIPException(ProblemException):
    """Bocked IP Exception Class."""

    def __init__(self, *, status=500, title=None, detail=None):
        ext = {'code': 6000}
        super().__init__(status=status, title=title, detail=detail, ext=ext)


class MaxRequestsException(ProblemException):
    """Bocked IP Exception Class."""

    def __init__(self, code):
        exc = WazuhTooManyRequests(code=code)
        ext = {'code': exc.code}
        ext.update({'remediation': exc.remediation} if hasattr(exc, 'remediation') else {})
        super().__init__(status=429, title=exc.title, detail=exc.message, type=exc.type, ext=ext)


class ExpectFailedException(ProblemException):
    """Exception for failed expectation (status code 417)."""

    def __init__(self, *, status=417, title=None, detail=None):
        ext = {'code': 417}
        super().__init__(status=status, title=title, detail=detail, ext=ext)
