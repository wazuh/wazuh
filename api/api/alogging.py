# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.wlogging import WazuhLogger
import logging
import re
from aiohttp.abc import AbstractAccessLogger

# compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+\]|\s+\*\s+')


class AccessLogger(AbstractAccessLogger):

    def log(self, request, response, time):
        self.logger.info(f'{request.get("user_name", "unknown_user")} '
                         f'{request.get("token", "unknown_token")} {request.remote} '
                         f'"{request.method} {request.path} '
                         f'done in {time*1000}ms: {response.status}')


class APILogger(WazuhLogger):
    """
    Defines the logger used by wazuh-apid
    """

    def __init__(self, *args, **kwargs):
        """
        Constructor
        """
        super().__init__(*args, **kwargs, tag='{asctime} {levelname}: {message}',
                         custom_formatter=APIFormatter)

    def setup_logger(self):
        """
        Set ups API logger. In addition to super().setup_logger() this method adds:
            * Sets up log level based on the log level defined in API configuration file.
        """
        super().setup_logger()

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
    # new_user = request.authorization['username'] if request.authorization else ''
    # wazuh_logger = logging.getLogger('aiohttp')
    # wazuh_logger.filters[0].update_user(new_user)
