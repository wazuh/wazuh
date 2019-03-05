# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


class APIException(Exception):
    """
    Wazuh API exception
    """
    def __init__(self, code: int, message: str = None):
        """
        Constructor
        :param code: Error code.
        :param message: Extra message to add to the default exception message.
        """
        self.code = code
        self.message = message
        self.exceptions = {
            2000: 'User API configuration contains extra values'
        }

    def __str__(self):
        extra_message = '.' if self.message is None else f': {self.message}.'
        return f"Error {self.code} - {self.exceptions[self.code]}{extra_message}"
