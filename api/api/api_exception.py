# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from api.constants import CONFIG_PATH, SECURITY_PATH


class APIException(Exception):
    """
    Wazuh API exception
    """
    def __init__(self, code: int, details: str = None):
        """
        Constructor
        :param code: Error code.
        :param details: Extra details to add to the default exception message to include useful context information
        """
        self.code = code
        self.details = details
        self.exceptions = {
            2000: f'Some parameters are not expected in the configuration file ({CONFIG_PATH})',
            2001: 'Error creating or reading secrets file. Please, ensure '
                  f'there is enough disk space and permission to write in {SECURITY_PATH}'
        }

    def __str__(self):
        details = '.' if self.details is None else f': {self.details}.'
        return f"Error {self.code} - {self.exceptions[self.code]}{details}"
