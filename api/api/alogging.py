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

# C0 control characters and DEL. Written raw to the plain-text log they start a forged
# entry or drive the terminal that displays the file.
control_chars_pattern = re.compile(r'[\x00-\x1f\x7f]')

logger = logging.getLogger('wazuh-api')

# Maximum size, in serialised bytes, of a request body that is written to the API logs. The same
# payload is written once to api.log and again to api.json, so logging it verbatim turns a single
# request into several times its size on disk. It is also the size above which the access logger
# refuses to buffer a body at all.
MAX_LOGGED_BODY_SIZE = 8 * 1024

# Field names whose value is masked before a request is written to the access log. Matched
# case-insensitively against the whole name and against a `<prefix>_<name>` tail, so `api_key`,
# `client_secret`, `x-api-key` and `accessToken` are all covered without the false positives
# (`keyword`, `monkey`, `tokenizer`) a plain substring test would bring.
SENSITIVE_FIELD_NAMES = frozenset({
    'authorization', 'cookie', 'credential', 'credentials', 'key', 'passwd', 'password',
    'pwd', 'secret', 'token',
})
SENSITIVE_FIELD_SUFFIXES = tuple(f'_{name}' for name in SENSITIVE_FIELD_NAMES)

# Value written in place of a sensitive one.
REDACTED_VALUE = '****'

# Fold a camelCase boundary to the `_` the suffix rule is written against. Identity-provider
# claims are routinely `accessToken`, `apiKey` or `clientSecret`. Hyphens, which header names
# use, are folded the same way.
_WORD_BOUNDARY = re.compile(r'(?<=[a-z0-9])(?=[A-Z])')


def is_sensitive_field(name: str) -> bool:
    """Check whether a field or header name designates a value that must not be logged.

    Parameters
    ----------
    name : str
        Field or header name.

    Returns
    -------
    bool
        True if the value behind this name must be masked before it is logged.
    """
    # Two spellings are tested, not one. Splitting camelCase first would mangle a name that is
    # already a match once lowercased -- `PaSsWoRd` splits into `pa_ss_wo_rd` and matches nothing,
    # though `.lower()` alone gives `password`. Testing both makes the rule strictly wider than
    # either half.
    for candidate in (name.lower().replace('-', '_'),
                      _WORD_BOUNDARY.sub('_', name).lower().replace('-', '_')):
        if candidate in SENSITIVE_FIELD_NAMES or candidate.endswith(SENSITIVE_FIELD_SUFFIXES):
            return True
    return False


def redact_sensitive_fields(value):
    """Return a copy of a parsed JSON value with every sensitive field masked, at any depth.

    A sensitive key masks its whole value, object or scalar. Lists are walked too, so a secret
    inside an array of objects is reached. Anything that is not a mapping or a list -- `None`, a
    bare scalar, a string -- is returned unchanged: a JSON body is not necessarily an object.

    The input is never modified. The body handed to the access log is the request's own cached
    `_json`, and `api/api/middlewares.py` hashes the `run_as` authorization context as received,
    so redaction must not reach back into it.

    The walk is iterative on purpose. A body nested 500 levels deep is accepted today
    (`tests/integration/test_api/test_miscs/test_recursion.py` asserts a 200 for it); a recursive
    walker would spend several Python frames per level on top of an already deep ASGI stack and
    raise `RecursionError` after the response had been built.

    Parameters
    ----------
    value : any
        Parsed JSON value: a mapping, a list, or a scalar.

    Returns
    -------
    any
        A copy of `value` with the value of every sensitive field replaced by `REDACTED_VALUE`.
    """
    if isinstance(value, dict):
        root = {}
    elif isinstance(value, list):
        root = []
    else:
        return value

    stack = [(value, root)]
    while stack:
        source, target = stack.pop()
        items = source.items() if isinstance(source, dict) else enumerate(source)

        for name, item in items:
            if isinstance(target, dict) and is_sensitive_field(name):
                child = REDACTED_VALUE
            elif isinstance(item, dict):
                child = {}
                stack.append((item, child))
            elif isinstance(item, list):
                child = []
                stack.append((item, child))
            else:
                child = item

            if isinstance(target, list):
                target.append(child)
            else:
                target[name] = child

    return root


def escape_control_chars(value: str) -> str:
    """Replace each control character with its Python escape sequence (`\\n`, `\\x1b`...)."""
    return control_chars_pattern.sub(lambda m: repr(m.group())[1:-1], value)


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
            "start-stop-api": {"handlers": hdls, "level": 'INFO', "propagate": False}
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
    body : any
        Parsed request body. A JSON body is not necessarily an object: `null`, a list and bare
        scalars are all valid, and all of them reach this function as they were parsed.
    elapsed_time : float
        Required time to compute the request.
    status : int
        Status code of the request.
    hash_auth_context : str, optional
        Hash representing the authorization context. Default: ''
    headers: dict
        Optional dictionary of request headers.
    """
    # Redact here rather than at the call site: the function that writes the log is the one that
    # masks, so no caller can forget to. `redact_sensitive_fields` returns a copy, which is what
    # lets `access_log` keep hashing the `run_as` authorization context as it was received.
    query = redact_sensitive_fields(query)
    body = redact_sensitive_fields(body)

    # Serialise the body once -- after masking, since this dump is what reaches api.log -- and
    # refuse to log an oversized one. The access logger already declines to buffer a body above
    # this size, but nothing else stops a caller of this function from handing over a payload that
    # would be written out verbatim, twice.
    body_dump = json.dumps(body)
    if len(body_dump) > MAX_LOGGED_BODY_SIZE:
        body = {'body_omitted': f'body of {len(body_dump)} serialised bytes exceeds the '
                                f'{MAX_LOGGED_BODY_SIZE} byte logging limit'}
        body_dump = json.dumps(body)

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

    # Only the plain-text line needs it: the JSON record is escaped by its formatter.
    user, path = escape_control_chars(str(user)), escape_control_chars(str(path))

    if not hash_auth_context:
        log_info = f'{user} {remote} "{method} {path}" '
    else:
        log_info = f'{user} ({hash_auth_context}) {remote} "{method} {path}" '
        json_info['hash_auth_context'] = hash_auth_context

    log_info += f'with parameters {json.dumps(query)} and body '\
                f'{body_dump} done in {elapsed_time:.3f}s: {status}'

    logger.info(log_info, extra={'log_type': 'log'})
    logger.info(json_info, extra={'log_type': 'json'})
    logger.debug2(f'Receiving headers {headers}')
