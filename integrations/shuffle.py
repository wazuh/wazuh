# Created by Shuffle, AS. <frikky@shuffler.io>.
# Based on the Slack integration using Webhooks
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Error Codes:
#   1 - Module requests not found
#   2 - Incorrect input arguments
#   3 - Alert File does not exist
#   4 - Error getting json_alert


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
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration structure
# <integration>
#  <name>shuffle</name>
#  <hook_url>http://IP:3001/api/v1/hooks/HOOK_ID</hook_url> <!-- Replace with your Shuffle hook URL -->
#  <level>3</level>
#  <alert_format>json</alert_format>
#  <options>JSON</options> <!-- Replace with your custom JSON object -->
# </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
SKIP_RULE_IDS = [
    '87924',
    '87900',
    '87901',
    '87902',
    '87903',
    '87904',
    '86001',
    '86002',
    '86003',
    '87932',
    '80710',
    '87929',
    '87928',
    '5710',
]

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(sys.argv) > 4 else '', args[5] if len(sys.argv) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

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

    Raises
    ------
    FileNotFoundError
        If no alert file or optional file are presents.
    JSONDecodeError
        If no valid JSON file are used
    """
    debug('# Running Shuffle script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''
    json_options: str = ''

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
    msg: str = generate_msg(json_alert, json_options)

    # Check if alert is skipped
    if isinstance(msg, str):
        if not msg:
            return

    debug(f'# Sending message {msg} to Shuffle server')
    send_msg(msg, webhook)


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


# Skips container kills to stop self-recursion
def filter_msg(alert) -> bool:
    # SKIP_RULE_IDS need to be filtered because Shuffle starts Docker containers, therefore those alerts are triggered

    return alert['rule']['id'] not in SKIP_RULE_IDS


def generate_msg(alert: any, options: any) -> str:
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
    if not filter_msg(alert):
        print('Skipping rule %s' % alert['rule']['id'])
        return ''

    level = alert['rule']['level']

    if level <= 4:
        severity = 1
    elif level >= 5 and level <= 7:
        severity = 2
    else:
        severity = 3

    msg = {
        'severity': severity,
        'pretext': 'WAZUH Alert',
        'title': alert['rule']['description'] if 'description' in alert['rule'] else 'N/A',
        'text': alert.get('full_log'),
        'rule_id': alert['rule']['id'],
        'timestamp': alert['timestamp'],
        'id': alert['id'],
        'all_fields': alert,
    }

    if options:
        msg.update(options)

    return json.dumps(msg)


def send_msg(msg: str, url: str) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the integration.
    """
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
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
