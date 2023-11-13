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
import logging
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import urlparse

# Exit error codes
ERR_NO_REQUEST_MODULE   = 1
ERR_INVALID_ARGUMENTS   = 2
ERR_FILE_NOT_FOUND      = 6
ERR_INVALID_JSON        = 7

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ModuleNotFoundError as e:
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
pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert      = {}
SKIP_RULE_IDS   = ["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932",
                 "80710", "87929", "87928", "5710"]

# Logger
LOG_FILE    = f'{pwd}/logs/integrations.log'
logger      = logging.getLogger("shuffle")

# Constants
ALERT_INDEX     = 1
WEBHOOK_INDEX   = 3


def main(args):
    try:
        # Read arguments
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

        if not is_valid_url(args[3]):
            raise Exception(f"Invalid webhook URL: {args[3]}")

        # Logging the call
        logger.debug(msg)

        # Core function
        process_args(args)

    except Exception as e:
        logger.error(str(e))
        raise


def process_args(args) -> None:
    """Create a message with all valid fields.

        Parameters
        ----------
        args : list[str]
            The argument list from main call.

        Raises
        ------
        FileNotFoundError
            If no alert file or optional file are presents.
        JSONDecodeError
            If no valid JSON file are used.
    """
    # Read args
    alert_file_location: str     = args[ALERT_INDEX]
    webhook: str                 = args[WEBHOOK_INDEX]
    options_file_location: str   = ''
    json_options: str            = ''

    logger.info("Running Shuffle script")
    logger.info("Alerts file location: %s", alert_file_location)
    logger.debug("Webhook: %s", webhook)

    # Look for options file location
    for idx in range(4, len(args)):
        if(args[idx][-7:] == "options"):
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    logger.debug("Opening options file at '%s' with '%s'", options_file_location, json_options)

    # Load alert. Parse JSON object.
    json_alert  = get_json_alert(alert_file_location)
    logger.info("Processing alert with ID %s", json_alert["id"])
    logger.debug("Opening alert file at '%s' with '%s'", alert_file_location, json_alert)

    msg: str = generate_msg(json_alert, json_options)

    # Check if alert is skipped
    if isinstance(msg, str):
        if not msg:
            return

    send_msg(msg, webhook)


# Skips container kills to stop self-recursion
def filter_msg(alert: object) -> bool:
    # SKIP_RULE_IDS need to be filtered because Shuffle starts Docker containers, therefore those alerts are triggered

    return not alert["rule"]["id"] in SKIP_RULE_IDS


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
    logger.info("Generating message")

    if not filter_msg(alert):
        logger.info("Skipping alert %s", alert["rule"]["id"])
        return ""

    level = alert['rule']['level']

    if (level <= 4):
        severity = 1
    elif (level >= 5 and level <= 7):
        severity = 2
    else:
        severity = 3

    msg = {'severity': severity, 'pretext': "WAZUH Alert",
           'title': alert['rule']['description'] if 'description' in alert['rule'] else "N/A",
           'text': alert.get('full_log'),
           'rule_id': alert["rule"]["id"],
           'timestamp': alert["timestamp"],
           'id': alert['id'], "all_fields": alert}

    if(options):
        msg.update(options)

    json_msg = json.dumps(msg)
    logger.debug("Message: %s", json_msg)

    return json_msg

def send_msg(msg: str, url: str) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the integration.
    """
    logger.info("Sending message")

    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res     = requests.post(url, data=msg, headers=headers, verify=False, timeout=5)
    if 200 <= res.status_code <= 299:
        logger.info("Message sent successfully")
    else:
        raise requests.HTTPError("Failed sending message", res.reason)
    
    logger.debug("Shuffle response: Date: %s, Status code: %d, URL: %s",
                 res.headers["date"], res.status_code, res.url)

def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

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
    help_msg = '''
    Exiting: Invalid arguments.

    Usage:
        shuffle <alerts_file> [api_key] <webhook_url> [logging_level] [options_file]
    Arguments:
        alerts_file (required)
            Path to the JSON file containing the alerts.
        api_key (not required)
            The API key argument is not needed for the Shuffle integration. However, it's still considered because the 
            integrator executes all scripts with the same arguments.
            If you are executing the script manually, please put anything in that argument.
        webhook_url (required)
            Shuffle webhook URL where the messages will be sent to.
        logging_level (optional)
            Used to define how much information should be logged. Default is INFO.
            Levels: NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL.
        options_file (optional)
            Path to a file containing custom variables to be used in the integration. It must be JSON-encoded.
    '''
    print(help_msg)


def is_valid_url(url: str) -> bool:
    """Validate a URL.

    Parameters
    ----------
    url: str
        Integration URL.

    Returns
    -------
    bool
        Whether the URL is valid or not.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

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
