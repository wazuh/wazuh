# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.wlogging import WazuhLogger
import logging
from flask import request


class APIFilter(logging.Filter):
    """
    Adds cluster related information into cluster logs.
    """
    def __init__(self, user: str = '', name: str = ''):
        """
        Class constructor

        :param user: API user doing the request
        :param name: If name is specified, it names a logger which, together with its children, will have its events
                     allowed through the filter. If name is the empty string, allows every event.
        """
        super().__init__(name=name)
        self.user = user

    def filter(self, record):
        record.user = self.user
        return True

    def update_user(self, new_user: str):
        self.user = f' {new_user} '


class APILogger(WazuhLogger):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.werkzeug_logger = logging.getLogger('werkzeug')
        self.flask_logger = logging.getLogger('Flask')
        self.filter = APIFilter()

    def setup_logger(self):
        super().setup_logger()
        logging.root.addHandler(logging.NullHandler())
        self.logger.addFilter(self.filter)
        self.werkzeug_logger.addFilter(self.filter)
        if self.debug_level == 'debug2':
            debug_level = logging.DEBUG2
        elif self.debug_level == 'debug':
            debug_level = logging.DEBUG
        elif self.debug_level == 'critical':
            debug_level = logging.CRITICAL
        elif self.debug_level == 'error':
            debug_level = logging.ERROR
        elif self.debug_level == 'warning':
            debug_level = logging.WARNING
        else:  # self.debug_level == 'info'
            debug_level = logging.INFO

        self.logger.setLevel(debug_level)
        self.werkzeug_logger.setLevel(debug_level)

        for h in self.logger.handlers:
            self.werkzeug_logger.addHandler(h)


def set_request_user_logs():
    """
    sets authenticated user in logs
    """
    if request.path == '/login':
        wazuh_logger = logging.getLogger('wazuh')
        wazuh_logger.filters[0].update_user(request.authorization['username'])
