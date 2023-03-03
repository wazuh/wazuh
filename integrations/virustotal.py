#!/usr/bin/env python
# Copyright (C) 2023, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


import json
import os
import sys
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# ossec.conf configuration:
#  <integration>
#      <name>virustotal</name>
#      <api_key>api_key_here</api_key>
#      <group>syscheck</group>
#      <alert_format>json</alert_format>
#      <options>JSON_OBJ</options>
#  </integration>

# Global vars
debug_enabled   = False
debug_console   = True
pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert      = {}
json_options    = {}
now             = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Log and socket path
LOG_FILE        = f'{pwd}/logs/integrations.log'
SOCKET_ADDR     = f'{pwd}/queue/sockets/queue'

# Constants
ALERT_INDEX     = 1
APIKEY_INDEX    = 2


def main(args: list[str]):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4} {5}'.format(
                now,
                args[1],
                args[2],
                args[3],
                args[4] if len(args) > 4 else '',
                args[5] if len(args) > 5 else ''
            )
            debug_enabled = (len(args) > 4 and args[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, "a") as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug("# Exiting: Bad arguments. Inputted: %s" % args)
            sys.exit(2)
        
        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise
    
def process_args(args: list[str]) -> None:
    """ 
        This is the core function, creates a message with all valid fields 
        and overwrite or add with the optional fields
        
        Parameters
        ----------
        args : list[str]
            The argument list from main call
    """
    debug("# Starting")
    
    # Read args
    alert_file_location:str     = args[ALERT_INDEX]
    apikey:str                  = args[APIKEY_INDEX]
    options_file_location:str   = ''
    
    # Look for options file location
    for idx in range(4,len(args)):
        if(args[idx][-7:] == "options"):
            options_file_location = args[idx]
            break

    debug("# Options file location")
    debug(options_file_location)
    
    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
        
    debug("# Processing options")
    debug(json_options)
    
    debug("# Alert file location")
    debug(alert_file_location)  

    # Load alert. Parse JSON object.            
    json_alert = get_json_alert(alert_file_location)

    debug("# Processing alert")
    debug(json_alert)

    debug("# Generating message")
    msg: any = generate_msg(json_alert, json_options,apikey)
    
    if not msg:
        debug("# ERR - Empty message")
        raise Exception
    
    debug("# Sending message")
    send_msg(msg,json_alert["agent"])

def debug(msg: str) -> None:
    """ 
        Log the message in the log file with the timestamp, if debug flag
        is enabled
        
        Parameters
        ----------
        msg : str
            The message to be logged.
    """
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg)
    if debug_console:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        
def generate_msg(alert: any, options: any,apikey:str) -> str:
    """ 
        Generate the JSON object with the message to be send

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
    msg = {}
    # If there is no a md5 checksum present in the alert. Exit.
    if not "md5_after" in alert["syscheck"]:
        debug("# Exiting: MD5 checksum not found in alert.")
        sys.exit(1)
    
    # Request info using VirusTotal API
    try:
        vt_response_data = query_api(alert["syscheck"]["md5_after"], apikey)
    except Exception as e:
        debug(e)
        sys.exit(2)
        
    msg["virustotal"]                           = {}
    msg["integration"]                          = "virustotal"
    msg["virustotal"]["found"]                  = 0
    msg["virustotal"]["malicious"]              = 0
    msg["virustotal"]["source"]                 = {}
    msg["virustotal"]["source"]["alert_id"]     = alert["id"]
    msg["virustotal"]["source"]["file"]         = alert["syscheck"]["path"]
    msg["virustotal"]["source"]["md5"]          = alert["syscheck"]["md5_after"]
    msg["virustotal"]["source"]["sha1"]         = alert["syscheck"]["sha1_after"]
    
    # Check if VirusTotal has any info about the hash
    if vt_response_data['response_code']:
        msg["virustotal"]["found"] = 1
    
    # Info about the file found in VirusTotal
    if msg["virustotal"]["found"] == 1:
        if vt_response_data['positives'] > 0:
            msg["virustotal"]["malicious"] = 1
        # Populate JSON Output object with VirusTotal request
        msg["virustotal"]["sha1"]           = vt_response_data['sha1']
        msg["virustotal"]["scan_date"]      = vt_response_data['scan_date']
        msg["virustotal"]["positives"]      = vt_response_data['positives']
        msg["virustotal"]["total"]          = vt_response_data['total']
        msg["virustotal"]["permalink"]      = vt_response_data['permalink']
        
    if(options):
        msg.update(options)
        
    return json.dumps(msg)

def query_api(hash: str, apikey: str) -> any:
    """ 
        Send a request to VT API and fetch information to build message
            
        Parameters
        ----------
        hash : str
            Hash need it for parameters
        apikey: str
            JSON options object.
               
        Returns
        -------
        data: any
            JSON with the response
            
        Raises
        ------
        Exception
            If the status code is different than 200.
    """
    params    = {'apikey': apikey, 'resource': hash}
    headers   = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  Python library-client-VirusTotal"
    }
    response  = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
  
    if response.status_code == 200:
        json_response = response.json()
        data = json_response
        return data
    else:
        alert_output                  = {}
        alert_output["virustotal"]    = {}
        alert_output["integration"]   = "virustotal"

        if response.status_code == 204:
          alert_output["virustotal"]["error"]         = response.status_code
          alert_output["virustotal"]["description"]   = "Error: Public API request rate limit reached"
          raise Exception("# Error: VirusTotal Public API request rate limit reached")
        elif response.status_code == 403:
          alert_output["virustotal"]["error"]         = response.status_code
          alert_output["virustotal"]["description"]   = "Error: Check credentials"
          raise Exception("# Error: VirusTotal credentials, required privileges error")
        else:
          alert_output["virustotal"]["error"]         = response.status_code
          alert_output["virustotal"]["description"]   = "Error: API request fail"
          raise Exception("# Error: VirusTotal credentials, required privileges error")

def send_msg(msg: any, agent:any) -> None:
    if not agent or agent["id"] == "000":
        string      = '1:virustotal:{0}'.format(msg)
    else:
        location    = '[{0}] ({1}) {2}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any")
        location    = location.replace("|", "||").replace(":", "|:")
        string      = '1:{0}->virustotal:{1}'.format(location,msg)

    debug("# Final msg to send: %s" % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug(" # Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(4)

def get_json_alert(alert_file_location: str) -> any:
    """ 
        Read the JSON object from alert file

        Parameters
        ----------
        alert_file_location : str
            Path to file alert location.
            
        Returns
        -------
        {}: any
            The JSON object read it.
        
        Raises
        ------
        FileNotFoundError
            If no alert file is not present.
        JSONDecodeError
            If no valid JSON file are used
    """
    try:
        with open(alert_file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# Alert file %s doesn't exist" % alert_file_location)
        sys.exit(3)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting json_alert %s" % e)
        sys.exit(4)
        
def get_json_options(options_file_location: str) -> any:
    """ 
        Read the JSON object from options file

        Parameters
        ----------
        options_file_location : str
            Path to file options location.
            
        Returns
        -------
        {}: any
            The JSON object read it.
        
        Raises
        ------
        FileNotFoundError
            If no optional file is not present.
        JSONDecodeError
            If no valid JSON file are used
    """
    try:
        with open(options_file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# Option file %s doesn't exist" % options_file_location)
        sys.exit(3)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting json_alert %s" % e)
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)