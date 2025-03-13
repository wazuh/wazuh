# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import re

from wazuh.core.config.models.logging import APILoggingConfig

from server_management_api.api_exception import APIError

# Compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

logger = logging.getLogger('wazuh-api')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = 'unknown_user'
WARNING = 'WARNING'
INFO = 'INFO'


def set_logging(logging_config: APILoggingConfig, tag: str) -> dict:
    """Set up logging for API.

    This function creates a logging configuration dictionary, configure the wazuh-api logger
    and returns the logging configuration dictionary that will be used in uvicorn logging
    configuration.

    Parameters
    ----------
    logging_config :  APILoggingConfig
        Logger configuration.
    tag : str
        Logger tag.

    Raises
    ------
    ApiError

    Returns
    -------
    log_config_dict : dict
        Logging configuration dictionary.
    """
    log_level = logging_config.get_level()
    handlers = {'console': {}}

    hdls = [k for k, v in handlers.items() if isinstance(v, dict)]
    if not hdls:
        raise APIError(2011)

    log_config_dict = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                '()': 'uvicorn.logging.DefaultFormatter',
                'fmt': '%(levelprefix)s %(message)s',
                'use_colors': None,
            },
            'access': {
                '()': 'uvicorn.logging.AccessFormatter',
                'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
            'log': {
                '()': 'uvicorn.logging.DefaultFormatter',
                'fmt': f'%(asctime)s %(levelname)s: [{tag}] %(message)s',
                'datefmt': '%Y/%m/%d %H:%M:%S',
                'use_colors': None,
            },
        },
        'filters': {'plain-filter': {'()': 'wazuh.core.wlogging.CustomFilter', 'log_type': 'log'}},
        'handlers': {
            'default': {
                'formatter': 'default',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stderr',
            },
            'access': {'formatter': 'access', 'class': 'logging.StreamHandler', 'stream': 'ext://sys.stdout'},
            'console': {
                'formatter': 'log',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout',
                'filters': ['plain-filter'],
            },
        },
        'loggers': {
            'wazuh': {'handlers': hdls, 'level': log_level, 'propagate': False},
            'wazuh-api': {'handlers': hdls, 'level': log_level, 'propagate': False},
            'wazuh-comms-api': {'handlers': hdls, 'level': log_level, 'propagate': False},
        },
    }

    # configure file handlers

    # Configure the uvicorn loggers. They will be created by the uvicorn server.
    log_config_dict['loggers']['uvicorn'] = {'handlers': hdls, 'level': WARNING, 'propagate': False}
    log_config_dict['loggers']['uvicorn.error'] = {'handlers': hdls, 'level': WARNING, 'propagate': False}
    log_config_dict['loggers']['uvicorn.access'] = {'level': WARNING}

    # Configure the gunicorn loggers. They will be created by the gunicorn process.
    log_config_dict['loggers']['gunicorn'] = {'handlers': hdls, 'level': INFO, 'propagate': False}
    log_config_dict['loggers']['gunicorn.error'] = {'handlers': hdls, 'level': INFO, 'propagate': False}
    log_config_dict['loggers']['gunicorn.access'] = {'level': INFO}

    return log_config_dict


def custom_logging(
    user, remote, method, path, query, body, elapsed_time, status, hash_auth_context='', headers: dict = None
):
    """Provide the log entry structure depending on the logging format.

    Parameters
    ----------
    user : str
        User who perform the request.
    remote : str
        IP address of the request.
    method : str
        HTTP method used in the request.
    path : str
        Endpoint used in the request.
    query : dict
        Dictionary with the request parameters.
    body : dict
        Dictionary with the request body.
    elapsed_time : float
        Required time to compute the request.
    status : int
        Status code of the request.
    hash_auth_context : str, optional
        Hash representing the authorization context. Default: ''
    headers: dict
        Optional dictionary of request headers.
    """
    json_info = {
        'user': user,
        'ip': remote,
        'http_method': method,
        'uri': f'{method} {path}',
        'parameters': query,
        'body': body,
        'time': f'{elapsed_time:.3f}s',
        'status_code': status,
    }

    if not hash_auth_context:
        log_info = f'{user} {remote} "{method} {path}" '
    else:
        log_info = f'{user} ({hash_auth_context}) {remote} "{method} {path}" '
        json_info['hash_auth_context'] = hash_auth_context

    if path == '/events' and logger.level >= 20:
        # If log level is info simplify the messages for the /events requests.
        if isinstance(body, dict):
            events = body.get('events', [])
            body = {'events': len(events)}
            json_info['body'] = body

    log_info += f'with parameters {json.dumps(query)} and body {json.dumps(body)} done in {elapsed_time:.3f}s: {status}'

    logger.info(log_info, extra={'log_type': 'log'})
    logger.info(json_info, extra={'log_type': 'json'})
    logger.debug2(f'Receiving headers {headers}')
