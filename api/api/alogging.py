# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import binascii
import json
import logging
import re
from base64 import b64decode

from aiohttp.abc import AbstractAccessLogger
from pythonjsonlogger import jsonlogger
from wazuh.core.wlogging import WazuhLogger

from api.configuration import api_conf

# compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

JSON_FORMAT = api_conf['logs']['format'] == 'json'


class AccessLogger(AbstractAccessLogger):
    """
    Defines the log writter used by aiohttp
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.custom_logging = self.setup_custom_logging()

    def setup_custom_logging(self):
        """Provides the log entry structure depending on the logging format"""
        def plain_log(user, remote, method, path, query, body, time, status):
            self.logger.info(f'{user} '
                             f'{remote} '
                             f'"{method} {path}" '
                             f'with parameters {json.dumps(query)} and body {json.dumps(body)} '
                             f'done in {time:.3f}s: {status}')

        def json_log(user, remote, method, path, query, body, time, status):
            self.logger.info({'user': user,
                              'remote_ip': remote,
                              'request_method': f'{method} {path}',
                              'request_parameters': query,
                              'request_body': body,
                              'time': f'{time:.3f}s',
                              'status_code': status
                              }
                             )

        return json_log if JSON_FORMAT else plain_log

    def log(self, request, response, time):
        query = dict(request.query)
        body = request.get("body", dict())
        if 'password' in query:
            query['password'] = '****'
        if 'password' in body:
            body['password'] = '****'
        if 'key' in body and '/agents' in request.path:
            body['key'] = '****'
        # With permanent redirect, not found responses or any response with no token information,
        # decode the JWT token to get the username
        user = request.get('user', '')
        if not user:
            try:
                user = b64decode(request.headers["authorization"].split()[1]).decode().split(':')[0]
            except (KeyError, IndexError, binascii.Error):
                user = UNKNOWN_USER_STRING

        self.custom_logging(user,
                            request.remote,
                            request.method,
                            request.path,
                            query,
                            body,
                            time,
                            response.status
                            )


class APILogger(WazuhLogger):
    """
    Defines the logger used by wazuh-apid
    """

    def __init__(self, *args, **kwargs):
        """
        Constructor
        """
        super().__init__(*args, **kwargs,
                         tag=f"%({'timestamp' if JSON_FORMAT else 'asctime'})s %(levelname)s: %(message)s",
                         custom_formatter=WazuhJsonFormatter if JSON_FORMAT else None)

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


class WazuhJsonFormatter(jsonlogger.JsonFormatter):
    """
    Defines the custom JSON log formatter used by wlogging
    """
    def add_fields(self, log_record, record, message_dict):
        # Request handling
        if record.message is None:
            record.message = message_dict
        else:
            # Traceback handling
            traceback = message_dict.get('exc_info')
            if traceback is not None:
                record.message = f"{record.message}. {traceback}"
        message_dict = {}
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
