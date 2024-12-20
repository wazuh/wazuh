# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


import json
import os
import re
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_VT = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
    from requests.exceptions import Timeout
except Exception:
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
debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}

# Log and socket path
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7


def main(args):
    global debug_enabled
    global timeout
    global retries
    try:
        # Read arguments
        bad_arguments: bool = False
        msg = ''
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == 'debug'
            if len(args) > TIMEOUT_INDEX:
                timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX:
                retries = int(args[RETRIES_INDEX])
        else:
            msg = '# Error: Wrong arguments\n'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg)

        if bad_arguments:
            debug('# Error: Exiting, bad arguments. Inputted: %s' % args)
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
    debug('# Running VirusTotal script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    apikey: str = args[APIKEY_INDEX]

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    # Request VirusTotal info
    debug('# Requesting VirusTotal information')
    msg: any = request_virustotal_info(json_alert, apikey)

    if not msg:
        debug('# Error: Empty message')
        raise Exception

    send_msg(msg, json_alert['agent'])


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


def request_info_from_api(alert, alert_output, api_key):
    """Request information from an API using the provided alert and API key.

    Parameters
    ----------
    alert : dict
        The alert dictionary containing information for the API request.
    alert_output : dict
        The output dictionary where API response information will be stored.
    api_key : str
        The API key required for making the API request.

    Returns
    -------
    dict
        The response data received from the API.

    Raises
    ------
    Timeout
        If the API request times out.
    Exception
        If an unexpected exception occurs during the API request.
    """
    for attempt in range(retries + 1):
        try:
            vt_response_data = query_api(alert['syscheck']['md5_after'], api_key)
            return vt_response_data
        except Timeout:
            debug('# Error: Request timed out. Remaining retries: %s' % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_VT)

    debug('# Error: Request timed out and maximum number of retries was exceeded')
    alert_output['virustotal']['error'] = 408
    alert_output['virustotal']['description'] = 'Error: API request timed out'
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_VT)


def request_virustotal_info(alert: any, apikey: str):
    """Generate the JSON object with the message to be send

    Parameters
    ----------
    alert : any
        JSON alert object.
    apikey : str
        The API key required for making the API request.

    Returns
    -------
    msg: str
        The JSON message to send
    """
    alert_output = {'virustotal': {}, 'integration': 'virustotal'}

    # If there is no syscheck block present in the alert. Exit.
    if 'syscheck' not in alert:
        debug('# No syscheck block present in the alert')
        return None

    # If there is no md5 checksum present in the alert. Exit.
    if 'md5_after' not in alert['syscheck']:
        debug('# No md5 checksum present in the alert')
        return None

    # If the md5_after field is not a md5 hash checksum. Exit
    if not (
        isinstance(alert['syscheck']['md5_after'], str) is True
        and len(re.findall(r'\b([a-f\d]{32}|[A-F\d]{32})\b', alert['syscheck']['md5_after'])) == 1
    ):
        debug('# md5_after field in the alert is not a md5 hash checksum')
        return None

    # Request info using VirusTotal API
    vt_response_data = request_info_from_api(alert, alert_output, apikey)

    alert_output['virustotal']['found'] = 0
    alert_output['virustotal']['malicious'] = 0
    alert_output['virustotal']['source'] = {
        'alert_id': alert['id'],
        'file': alert['syscheck']['path'],
        'md5': alert['syscheck']['md5_after'],
        'sha1': alert['syscheck']['sha1_after'],
    }

    # Check if VirusTotal has any info about the hash
    if vt_response_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious') != None:
        alert_output['virustotal']['found'] = 1

    # Info about the file found in VirusTotal
    if alert_output['virustotal']['found'] == 1:
        if vt_response_data['attributes']['last_analysis_stats']['malicious'] > 0:
            alert_output['virustotal']['malicious'] = 1

        # Populate JSON Output object with VirusTotal request
        alert_output['virustotal'].update(
            {
                'sha1': vt_response_data['attributes']['sha1'],
                'scan_date': vt_response_data['attributes']['last_analysis_date'],
                'positives': vt_response_data['attributes']['last_analysis_stats']['malicious'],
                'total': vt_response_data['attributes']['last_analysis_stats']['malicious'],
                'permalink': f"https://www.virustotal.com/gui/file/{alert['syscheck']['md5_after']}/detection",
            }
        )

    return alert_output


def query_api(hash: str, apikey: str) -> any:
    """Send a request to VT API and fetch information to build message

    Parameters
    ----------
    hash : str
        Hash need it for parameters
    apikey: str
        Authentication API key

    Returns
    -------
    data: any
        JSON with the response

    Raises
    ------
    Exception
        If the status code is different than 200.
    """
    headers = {'accept': 'application/json', 'x-apikey': apikey}

    debug('# Querying VirusTotal API')
    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash}', headers=headers, timeout=timeout)

    if response.status_code == 200:
        json_response = response.json()
        return json_response['data']
    else:
        alert_output = {}
        alert_output['virustotal'] = {}
        alert_output['integration'] = 'virustotal'

        if response.status_code == 429:
            alert_output['virustotal']['error'] = response.status_code
            alert_output['virustotal']['description'] = 'Error: Public API request rate limit reached'
            send_msg(alert_output)
            raise Exception('# Error: VirusTotal Public API request rate limit reached')
        elif response.status_code == 401:
            alert_output['virustotal']['error'] = response.status_code
            alert_output['virustotal']['description'] = 'Error: Check credentials'
            send_msg(alert_output)
            raise Exception('# Error: VirusTotal credentials, required privileges error')
        else:
            alert_output['virustotal']['error'] = response.status_code
            alert_output['virustotal']['description'] = 'Error: API request fail'
            send_msg(alert_output)
            raise Exception('# Error: VirusTotal credentials, required privileges error')


def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent['id'] == '000':
        string = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any')
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))

    debug('# Request result from VT server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


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


if __name__ == '__main__':
    main(sys.argv)
