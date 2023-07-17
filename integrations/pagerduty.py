# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import os
import sys
import logging
from logging.handlers import TimedRotatingFileHandler

# Exit error codes
ERR_NO_REQUEST_MODULE   = 1
ERR_INVALID_ARGUMENTS   = 2
ERR_FILE_NOT_FOUND      = 6
ERR_INVALID_JSON        = 7

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
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
pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert      = {}
json_options    = {}

# Logger
LOG_FILE    = f'{pwd}/logs/integrations.log'
logger      = logging.getLogger("pagerduty")

# Constants
ALERT_INDEX     = 1
APIKEY_INDEX    = 2
WEBHOOK = 'https://events.pagerduty.com/v2/enqueue'


def main(args):
    try:
        # Read arguments
        invalid_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1],
                args[2],
                args[3],
                args[4].upper() if len(args) > 4 else 'INFO',
                args[5] if len(sys.argv) > 5 else ''
            )
        else:
            print_help_msg()
            sys.exit(ERR_INVALID_ARGUMENTS)
        
        setup_logger(args)

        if not os.path.exists(args[1]):
            raise FileNotFoundError(f"Alert file specified {args[1]} does not exist")

        # Logging the call
        logger.debug(msg)

        # Core function
        process_args(args)

    except Exception as e:
        logger.error(str(e))
        raise

def process_args(args) -> None:
    """Create a message with all valid fields and overwrite or add the optional fields.

    Parameters
    ----------
    args : list[str]
        The argument list from main call.
    """
    # Read args
    alert_file_location: str    = args[ALERT_INDEX]
    apikey: str                 = args[APIKEY_INDEX]
    json_options: str           = ''
    options_file_location: str  = ''
    
    logger.info("Running PagerDuty script")
    logger.info("Alerts file location: %s", alert_file_location)
    logger.debug("API key: %s", apikey)

    # Look for options file location
    for idx in range(4, len(args)):
        if(args[idx][-7:] == "options"):
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    if options_file_location is not '':
        json_options = get_json_options(options_file_location)
        logger.debug("Opening options file at '%s' with '%s'", options_file_location, json_options)

    # Load alert. Parse JSON object.
    json_alert  = get_json_alert(alert_file_location)
    logger.info("Processing alert with ID %s", json_alert["id"])
    logger.debug("Opening alert file at '%s' with '%s'", alert_file_location, json_alert)

    msg: any = generate_msg(json_alert, json_options, apikey)
    send_msg(msg)

def generate_msg(alert: any, options: any, apikey: str) -> str:
    """Generate the JSON object with the message to be sent.

    Parameters
    ----------
    alert : any
        JSON alert object.
    options: any
        JSON options object.

    Returns
    -------
    msg: str
        The JSON message to send.
    """
    logger.info("Generating message")

    managed_security_url    = 'https://wazuh.com'
    level                   = alert['rule']['level']

    severity = 'info'
    if level >= 7:
        severity = 'warning'
    elif level >= 10:
        severity = 'error'
    elif level >= 13:
        severity = 'critical'

    groups = ', '.join(alert['rule']['groups'])

    msg = {
        'routing_key':  apikey,
        'event_action': 'trigger',
        'payload': {
            "summary": alert['rule']['description'] if 'description' in alert['rule'] else "N/A",
            "timestamp": alert['timestamp'],
            "source": alert['agent']['name'],
            "severity": severity,
            "group": groups,
            "custom_details": alert
        },
        "client": "Wazuh Monitoring Service",
        "client_url": managed_security_url
    }

    if (options):
        msg.update(options)

    json_msg = json.dumps(msg)
    logger.debug("Message: %s", json_msg)

    return json_msg

def send_msg(msg: any) -> None:
    """Send the message to the API.

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the API.
    """
    logger.info("Sending message")

    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res     = requests.post(WEBHOOK, data=msg, headers=headers, timeout=5)
    if 200 <= res.status_code <= 299:
        logger.info("Message sent successfully")
    else:
        raise requests.HTTPError("Failed sending message", res.reason)

    logger.debug("PagerDuty response: %s", res)

def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file.

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    any
        JSON encoded alert.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file is used.
    """
    try:
        with open(file_location, encoding='utf-8') as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        logger.error("JSON file for alert %s doesn't exist", file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        logger.error("Failed getting JSON alert. Error: %s", e)
        sys.exit(ERR_INVALID_JSON)

def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file is used
    """
    try:
        with open(file_location, encoding='utf-8') as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        logger.error("JSON file for options %s doesn't exist", file_location)
    except BaseException as e:
        logger.error("Failed getting JSON options. Error: %s", e)
        sys.exit(ERR_INVALID_JSON)

def print_help_msg():
    """Send the command's help message to the standard output."""
    help_msg = f'''
    Exiting: Invalid arguments.

    Usage:
        pagerduty  <alerts_file> <api_key> [webhook_url] [options_file]
        
    Arguments:
        alerts_file (required)
            Path to the JSON file containing the alerts.
        api_key (required)
            Pagerduty API key.
        webhook_url (optional)
            Pagerduty webhook URL where the messages will be sent to. Default is {WEBHOOK}.
        logging_level (optional)
            Used to define how much information should be logged. Default is INFO.
            Levels: NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL.
        options_file (optional)
            Path to a file containing custom variables to be used in the integration. It must be JSON-encoded.
    '''
    print(help_msg)

def setup_logger(args):
    """Configure the logger.

    Parameters
    ----------
    args: any
        Command arguments.
    """
    # Create log file directories if they do not exist
    log_file_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_file_dir):
        os.makedirs(log_file_dir)

    consoleHandler = logging.StreamHandler()
    fileHandler = TimedRotatingFileHandler(LOG_FILE, when='midnight', backupCount=31)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%a %b %d %H:%M:%S %Z %Y")
    consoleHandler.setFormatter(formatter)
    fileHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)
    logger.addHandler(fileHandler)

    if len(args) > 4:
        logger.setLevel(args[4].upper())
    else:
        logger.setLevel(logging.INFO)

if __name__ == "__main__":
    main(sys.argv)
