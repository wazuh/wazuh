# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import collections
import logging
import json
import re
from pythonjsonlogger import jsonlogger

from api.configuration import api_conf
from api.api_exception import APIError

# Compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

logger = logging.getLogger('wazuh-api')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"


class APILoggerSize:
    size_regex = re.compile(r"(\d+)([KM])")
    unit_conversion = {
        'K': 1024,
        'M': 1024 ** 2
    }

    def __init__(self, size_string: str):
        size_string = size_string.upper()
        try:
            size, unit = self.size_regex.match(size_string).groups()
        except AttributeError:
            raise APIError(2011, details="Size value does not match the expected format: <number><unit> (Available"
                                         " units: K (kilobytes), M (megabytes). For instance: 45M") from None

        self.size = int(size) * self.unit_conversion[unit]
        if self.size < self.unit_conversion['M']:
            raise APIError(2011, details=f"Minimum value for size is 1M. Current: {size_string}")


class WazuhJsonFormatter(jsonlogger.JsonFormatter):
    """
    Define the custom JSON log formatter used by wlogging.
    """

    def add_fields(self, log_record: collections.OrderedDict, record: logging.LogRecord, message_dict: dict):
        """Implement custom logic for adding fields in a log entry.

        Parameters
        ----------
        log_record : collections.OrderedDict
            Dictionary with custom fields used to generate a log entry.
        record : logging.LogRecord
            Contains all the information to the event being logged.
        message_dict : dict
            Dictionary with a request or exception information.
        """
        # Request handling
        if record.message is None:
            record.message = {
                'type': 'request',
                'payload': message_dict
            }
        else:
            # Traceback handling
            traceback = message_dict.get('exc_info')
            if traceback is not None:
                record.message = {
                    'type': 'error',
                    'payload': f'{record.message}. {traceback}'
                }
            else:
                # Plain text messages
                record.message = {
                    'type': 'informative',
                    'payload': record.message
                }
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
        log_record['levelname'] = record.levelname
        log_record['data'] = record.message


def set_logging(log_filepath, log_level='INFO', foreground_mode=False) -> dict:
    """Set up logging for API.
    
    This function creates a logging configuration dictionary, configure the wazuh-api logger
    and returns the logging configuration dictionary that will be used in uvicorn logging
    configuration.
    
    Parameters
    ----------
    log_path : str
        Log file path.
    log_level :  str
        Logger Log level.
    foreground_mode : bool
        Log output to console streams when true
        else Log output to file.

    Raise
    -----
    ApiError

    Returns
    -------
    log_config_dict : dict
        Logging configuration dictionary.
    """
    handlers = {
        'plainfile': None, 
        'jsonfile': None,
    }
    if foreground_mode:
        handlers.update({'console': {}})

    if 'json' in api_conf['logs']['format']:
        handlers["jsonfile"] = {
            'filename': f"{log_filepath}.json",
            'formatter': 'json',
            'filters': ['json-filter'],
        }
    if 'plain' in api_conf['logs']['format']:
        handlers["plainfile"] = {
            'filename': f"{log_filepath}.log",
            'formatter': 'log',
            'filters': ['plain-filter'],
        }

    hdls = [k for k, v in handlers.items() if isinstance(v, dict)]
    if not hdls:
        raise APIError(2011)

    log_config_dict = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
            "log": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(asctime)s %(levelname)s: %(message)s",
                "datefmt": "%Y/%m/%d %H:%M:%S",
                "use_colors": None,
            },
            "json" : {
                '()': 'api.alogging.WazuhJsonFormatter',
                'style': '%',
                'datefmt': "%Y/%m/%d %H:%M:%S"
            }
        },
        "filters": {
            'plain-filter': {'()': 'wazuh.core.wlogging.CustomFilter',
                             'log_type': 'log' },
            'json-filter': {'()': 'wazuh.core.wlogging.CustomFilter',
                             'log_type': 'json' }
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            },
            "console": {
                'formatter': 'log',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout',
                'filters': ['plain-filter']
            },
        },
        "loggers": {
            "wazuh-api": {"handlers": hdls, "level": log_level, "propagate": False},
            "start-stop-api": {"handlers": hdls, "level": 'INFO', "propagate": False},
            "wazuh-comms-api": {"handlers": hdls, "level": log_level, "propagate": False}
        }
    }

    # configure file handlers
    for handler, d in handlers.items():
        if d and 'filename' in d:
            if api_conf['logs']['max_size']['enabled']:
                max_size = APILoggerSize(api_conf['logs']['max_size']['size']).size
                d.update({
                    'class':'wazuh.core.wlogging.SizeBasedFileRotatingHandler',
                    'maxBytes': max_size,
                    'backupCount': 1
                })
            else:
                d.update({
                    'class': 'wazuh.core.wlogging.TimeBasedFileRotatingHandler',
                    'when': 'midnight'
                })
            log_config_dict['handlers'][handler] = d

    # Configure the uvicorn loggers. They will be created by the uvicorn server.
    log_config_dict['loggers']['uvicorn'] = {"handlers": hdls, "level": 'WARNING', "propagate": False}
    log_config_dict['loggers']['uvicorn.error'] = {"handlers": hdls, "level": 'WARNING', "propagate": False}
    log_config_dict['loggers']['uvicorn.access'] = {'level': 'WARNING'}

    # Configure the gunicorn loggers. They will be created by the gunicorn process.
    log_config_dict['loggers']['gunicorn'] = {"handlers": hdls, "level": log_level, "propagate": False}
    log_config_dict['loggers']['gunicorn.error'] = {"handlers": hdls, "level": log_level, "propagate": False}
    log_config_dict['loggers']['gunicorn.access'] = {'level': log_level}

    return log_config_dict


def custom_logging(user, remote, method, path, query,
                    body, elapsed_time, status, hash_auth_context='',
                    headers: dict = None):
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
        'status_code': status
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

    log_info += f'with parameters {json.dumps(query)} and body '\
                f'{json.dumps(body)} done in {elapsed_time:.3f}s: {status}'

    logger.info(log_info, extra={'log_type': 'log'})
    logger.info(json_info, extra={'log_type': 'json'})
    logger.debug2(f'Receiving headers {headers}')
