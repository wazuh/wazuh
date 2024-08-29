# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import os
import sys

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration structure
# <integration>
#   <name>pagerduty</name>
#   <api_key>API_KEY</api_key> <!-- Replace with your PagerDuty API key -->
#   <options>JSON</options> <!-- Replace with your custom JSON object -->
#   <alert_format>json</alert_format> <!-- With the new script this is mandatory -->
# </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        msg = ''
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments\n'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg)

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running PagerDuty script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    apikey: str = args[APIKEY_INDEX]
    options_file_location: str = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug('# Generating message')
    msg: any = generate_msg(json_alert, json_options, apikey)

    if not len(msg):
        debug('# ERROR: Empty message')
        raise Exception

    debug(f'# Sending message {msg} to PagerDuty server')
    send_msg(msg)


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def generate_msg(alert: any, options: any, apikey: str) -> str:
    """Generate the JSON object with the message to be send

    Parameters
    ----------
    alert : any
        JSON alert object.
    options: any
        JSON options object.

    Returns
    -------
    msg: str
        The JSON message to send
    """
    managed_security_url = 'https://wazuh.com'
    level = alert['rule']['level']

    severity = 'info'
    if level >= 7:
        severity = 'warning'
    elif level >= 10:
        severity = 'error'
    elif level >= 13:
        severity = 'critical'

    groups = ', '.join(alert['rule']['groups'])

    msg = {
        'routing_key': apikey,
        'event_action': 'trigger',
        'payload': {
            'summary': alert['rule']['description'] if 'description' in alert['rule'] else 'N/A',
            'timestamp': alert['timestamp'],
            'source': alert['agent']['name'],
            'severity': severity,
            'group': groups,
            'custom_details': alert,
        },
        'client': 'Wazuh Monitoring Service',
        'client_url': managed_security_url,
    }

    if options:
        msg.update(options)

    return json.dumps(msg)


def send_msg(msg: any) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the API.
    """

    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    url = 'https://events.pagerduty.com/v2/enqueue'
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
