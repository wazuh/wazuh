# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


import json
import sys
import logging
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import urlparse
import os
import re
from socket import socket, AF_UNIX, SOCK_DGRAM

# Exit error codes
ERR_NO_REQUEST_MODULE   = 1
ERR_INVALID_ARGUMENTS   = 2
ERR_BAD_MD5_SUM         = 3
ERR_NO_RESPONSE_VT      = 4
ERR_SOCKET_OPERATION    = 5
ERR_FILE_NOT_FOUND      = 6
ERR_INVALID_JSON        = 7

try:
    import requests
    from requests.auth import HTTPBasicAuth
    from requests.exceptions import Timeout
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration:
# <integration>
#   <name>virustotal</name>
#   <api_key>API_KEY</api_key> <!-- Replace with your VirusTotal API key -->
#   <group>syscheck</group>
#   <alert_format>json</alert_format>
# </integration>

# Global vars
timeout         = 10
retries         = 3
pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert      = {}
logger = logging.getLogger("virustotal")

# Log and socket path
LOG_FILE        = f'{pwd}/logs/integrations.log'
SOCKET_ADDR     = f'{pwd}/queue/sockets/queue'

# Constants
ALERT_INDEX     = 1
APIKEY_INDEX    = 2
TIMEOUT_INDEX   = 6
RETRIES_INDEX   = 7

def main(args):
    global timeout
    global retries
    try:
        # Read arguments
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4} {5} {6}'.format(
                args[1],
                args[2],
                args[3],
                args[4].upper() if len(args) > 4 else 'INFO',
                args[5] if len(sys.argv) > 5 else '',
                args[TIMEOUT_INDEX] if len(args) > TIMEOUT_INDEX else timeout,
                args[RETRIES_INDEX] if len(args) > RETRIES_INDEX else retries,
            )
            if len(args) > TIMEOUT_INDEX: timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX: retries = int(args[RETRIES_INDEX])
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
    alert_file_location: str     = args[ALERT_INDEX]
    apikey: str                  = args[APIKEY_INDEX]

    logger.info("Running VirusTotal script")
    logger.info("Alerts file location: %s", alert_file_location)
    logger.debug("API key: %s", apikey)

    # Load alert. Parse JSON object.
    json_alert  = get_json_alert(alert_file_location)
    logger.info("Processing alert with ID %s", json_alert["id"])
    logger.debug("Opening alert file at '%s' with '%s'", alert_file_location, json_alert)

    msg: any = generate_msg(json_alert, apikey)
    send_msg(msg, json_alert['agent'])

def generate_msg(alert: any, apikey: str):
    """Generate the JSON object with the message to be sent.

    Parameters
    ----------
    alert : any
        JSON alert object.

    Returns
    -------
    msg: str
        The JSON message to send.
    """
    logger.info("Generating message")

    request_ok                    = False
    alert_output                  = {}
    alert_output["virustotal"]    = {}
    alert_output["integration"]   = "virustotal"

    # If there is no syscheck block present in the alert. Exit.
    if not "syscheck" in alert:
        logger.debug("No syscheck block present in the alert")
        return None

    # If there is no md5 checksum present in the alert. Exit.
    if not "md5_after" in alert["syscheck"]:
        raise Exception("No md5 checksum present in the alert")

    # If the md5_after field is not a md5 hash checksum. Exit
    if not (isinstance(alert["syscheck"]["md5_after"],str) is True and
            len(re.findall(r'\b([a-f\d]{32}|[A-F\d]{32})\b', alert["syscheck"]["md5_after"])) == 1) :
        raise Exception("md5_after field in the alert is not a md5 hash checksum")

    # Request info using VirusTotal API
    for attempt in range(retries + 1):
        try:
            vt_response_data = query_api(alert["syscheck"]["md5_after"], apikey)
            request_ok = True
            break
        except Timeout:
            logger.error("Request timed out. Remaining retries: %s" % (retries - attempt))
            continue
        except Exception as e:
            logger.error(str(e))
            sys.exit(ERR_NO_RESPONSE_VT)

    if not request_ok:
        logger.error("Request timed out and maximum number of retries was exceeded")
        alert_output["virustotal"]["error"]         = 408
        alert_output["virustotal"]["description"]   = "Error: API request timed out"
        send_msg(alert_output)
        sys.exit(ERR_NO_RESPONSE_VT)

    alert_output["virustotal"]["found"]                  = 0
    alert_output["virustotal"]["malicious"]              = 0
    alert_output["virustotal"]["source"]                 = {}
    alert_output["virustotal"]["source"]["alert_id"]     = alert["id"]
    alert_output["virustotal"]["source"]["file"]         = alert["syscheck"]["path"]
    alert_output["virustotal"]["source"]["md5"]          = alert["syscheck"]["md5_after"]
    alert_output["virustotal"]["source"]["sha1"]         = alert["syscheck"]["sha1_after"]

    # Check if VirusTotal has any info about the hash
    if in_database(vt_response_data, hash):
        alert_output["virustotal"]["found"] = 1

    # Info about the file found in VirusTotal
    if alert_output["virustotal"]["found"] == 1:
        if vt_response_data['positives'] > 0:
            alert_output["virustotal"]["malicious"] = 1
        # Populate JSON Output object with VirusTotal request
        alert_output["virustotal"]["sha1"]           = vt_response_data['sha1']
        alert_output["virustotal"]["scan_date"]      = vt_response_data['scan_date']
        alert_output["virustotal"]["positives"]      = vt_response_data['positives']
        alert_output["virustotal"]["total"]          = vt_response_data['total']
        alert_output["virustotal"]["permalink"]      = vt_response_data['permalink']

    return alert_output

def in_database(data, hash):
    result = data['response_code']
    if result == 0:
        return False
    return True

def query_api(hash: str, apikey: str) -> any:
    """Send a request to VT API and fetch information to build message.

    Parameters
    ----------
    hash : str
        Hash needed for the parameters.
    apikey: str
        Authentication API.

    Returns
    -------
    data: any
        JSON with the response.

    Raises
    ------
    Exception
        If the status code is different than 200.
    """
    params    = {'apikey': apikey, 'resource': hash}
    headers   = { "Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  Python library-client-VirusTotal" }

    logger.debug("Querying VirusTotal API")
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers, timeout=timeout)

    if response.status_code == 200:
        json_response = response.json()
        vt_response_data = json_response
        return vt_response_data
    
    alert_output                        = {}
    alert_output["virustotal"]          = {}
    alert_output["integration"]         = "virustotal"
    alert_output["virustotal"]["error"] = response.status_code

    if response.status_code == 204:
        alert_output["virustotal"]["description"]   = "Error: Public API request rate limit reached"
        error = 'Error: VirusTotal Public API request rate limit reached'

    elif response.status_code == 403:
        alert_output["virustotal"]["description"]   = "Error: Check credentials"
        error = 'Error: VirusTotal credentials, required privileges error'
 
    else:
        alert_output["virustotal"]["description"]   = "Error: API request fail"
        error = 'Error: VirusTotal credentials, required privileges error'

    send_msg(json.dumps(alert_output))

    logger.error(error)
    raise Exception(error)

def send_msg(msg: any, agent:any = None) -> None:
    logger.info("Sending message")

    if not agent or agent["id"] == "000":
        string      = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        location    = '[{0}] ({1}) {2}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any")
        location    = location.replace("|", "||").replace(":", "|:")
        string      = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))

    logger.debug("Event: %s", string)

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        logger.error("Error: Unable to open socket connection at %s", SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)

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

def print_help_msg():
    """Send the command's help message to the standard output."""
    help_msg = '''
    Exiting: Invalid arguments.

    Usage:
        virustotal <alerts_file> <api_key> [webhook_url] [logging_level] [options_file]
    Arguments:
        alerts_file (required)
            Path to the JSON file containing the alerts.
        api_key (required)
            Virus total API key.
        webhook_url (not required)
            The webhook URL argument is not needed for the Virus total integration. However, it's still considered because the 
            integrator executes all scripts with the same arguments.
            If you are executing the script manually, please put anything in that argument.
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
