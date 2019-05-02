# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.wlogging import WazuhLogger
import logging
from flask import request
import re

# compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+\]|\s+\*\s+')


class APIFilter(logging.Filter):
    """
    Adds API related information into api logs.
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
        self.user = f' {new_user}'


class APILogger(WazuhLogger):
    """
    Defines the logger used by wazuh-apid
    """

    def __init__(self, *args, **kwargs):
        """
        Constructor
        """
        super().__init__(*args, **kwargs, tag='{asctime} {levelname}:{user} {message}',
                         custom_formatter=APIFormatter)
        self.werkzeug_logger = logging.getLogger('werkzeug')
        self.filter = APIFilter()

    def setup_logger(self):
        """
        Set ups API logger. In addition to super().setup_logger() this method adds:
            * A null handler to the root logger so the werkzeug doesn't add a stream handler to the root logger.
            * A filter to both API logger and werkzeug logger to add authenticated user to API logs.
            * Sets up log level based on the log level defined in API configuration file.
            * Adds handlers configured in super().setup_logger() to the werkzeug logger.
            * Modifies werkzeug logger info function to remove extra information from log messages.
        """
        super().setup_logger()
        # add a null handler to the root logger so the werkzeug logger doesnt create a stream handler.
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

        def info_werkzeug(msg, *args, **kwargs):
            """
            Modifies werkzeug logger info function to remove extra information from log messages:
                before: 127.0.0.1 - - [04/Mar/2019 13:27:37] "GET /token?pretty HTTP/1.1" 500 -
                after: 127.0.0.1 - - "GET /token?pretty HTTP/1.1" 500 -
                ---
                before: * Running on http://0.0.0.0:55000/ (Press CTRL+C to quit)
                After: Running on http://0.0.0.0:55000/ (Press CTRL+C to quit)
            """
            if self.werkzeug_logger.isEnabledFor(logging.INFO):
                self.werkzeug_logger._log(logging.INFO, request_pattern.sub('', msg), args, **kwargs)
        self.werkzeug_logger.info = info_werkzeug


class APIFormatter(logging.Formatter):
    """
    Custom formatter to ignore logging format when message comes from uWSGI
    """

    def format(self, record):
        message = record.getMessage()
        if "[UWSGI]" in message:
            return message
        else:
            return super().format(record)


def set_request_user_logs():
    """
    sets authenticated user in logs
    """
    new_user = request.authorization['username'] if request.authorization else ''
    wazuh_logger = logging.getLogger('wazuh')
    wazuh_logger.filters[0].update_user(new_user)
