#!/usr/bin/python3
# Created and Maintained by Roney Dsilva
# Example Use:
#  <active-response>
#     <disabled>no</disabled>
#     <command>cloudflare-ban</command>
#     <location>server</location>
#     <rules_id>31151,31152,31153,31154</rules_id>
#     <timeout>10</timeout>
#  </active-response>
#    <command>
#     <name>cloudflare-ban</name>
#     <executable>cloudflare-ban.py</executable>
#     <timeout_allowed>yes</timeout_allowed>
#  </command>

import os
import sys
import json
import requests
import datetime
from pathlib import PureWindowsPath, PurePosixPath

# Define a mapping of agent names to Cloudflare Zone IDs and Domains
agent_mapping = {
    "checkz-dev": {
        "zone_id": "ZONE_ID",
        "domain": "example1.com"  # Add the appropriate domain for the agent
    },
    "production": {
        "zone_id": "ANOTHER_ZONE_ID",
        "domain": "example2.com"  # Add the appropriate domain for the agent
    },
    # Add more mappings as needed
}

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg +"\n")


def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    #write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)
    return message


def send_keys_and_check_message(argv, keys):

    # build and send message with keys
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    #write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret

# Function to handle API errors
def handle_api_error(response, action):
    if response.status_code == 200:
        return True
    sys.exit(1)

def main(argv):

    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    alert = msg.alert["parameters"]["alert"]
    ip = alert["data"]["srcip"]
    agent_name = alert["agent"]["name"]
    keys = [alert["rule"]["id"],ip]


    agent_info = agent_mapping.get(agent_name, {})
    ZONE_ID = agent_info.get("zone_id")
    domain = agent_info.get("domain")

    if ZONE_ID is None or domain is None:
        sys.exit(OS_INVALID)

    TOKEN = 'F0Jq512QyMcy9i8EzcebMM-BLV3-_xn3UPMld9TL'
    MODE = 'block'  # block or challenge


    if msg.command == ADD_COMMAND:

        """ Start Custom Key
        At this point, it is necessary to select the keys from the alert and add them into the keys array.
        """

        """ End Custom Key """

        action = send_keys_and_check_message(argv, keys)

        # if necessary, abort execution
        if action != CONTINUE_COMMAND:

            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        """ Start Custom Action Add """

        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json"
        }
        # Adding the IP to null route
        data = [
            {
                "filter": {
                    "expression": f"(http.host eq \"{domain}\" and ip.src eq {ip})"
                },
                "action": MODE,
                "description": f"Added via OSSEC Command Block IP {ip} ({domain})"
            }
        ]
        try:
            response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules", headers=headers, json=data)
            if handle_api_error(response, "add"):
                write_debug_file(argv[0], "IP added to null route successfully")
                sys.exit(0)
        except requests.exceptions.RequestException as e:
            # This exception will catch various request-related issues, including network errors
            write_debug_file(argv[0], f"Request failed: {e}")
        except Exception as e:
            # This will catch other unexpected exceptions
            write_debug_file(argv[0], f"An unexpected error occurred: {e}")
        if response.status_code == 200:
            write_debug_file(argv[0], "Adding Completed")
        else:
            write_debug_file(argv[0], "Adding Rule Failed")
            sys.exit(1)

        """ End Custom Action Add """

    elif msg.command == DELETE_COMMAND:
        """ Start Custom Action Delete """

        # Deleting from null route
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json"
        }
        params = {
            "action": MODE,
            "description": f"Added via OSSEC Command Block IP {ip} ({domain})"
        }

        try:
            response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules", headers=headers, params=params)

        except requests.exceptions.RequestException as e:
            # This exception will catch various request-related issues, including network errors
            write_debug_file(argv[0], f"Get rule request failed: {e}")
        except Exception as e:
            # This will catch other unexpected exceptions
            write_debug_file(argv[0], f"Get rule failed with unknown error: {e}")

        if response.status_code == 200:
            data = response.json()
            if data.get("result"):
                rule_id = data["result"][0]["id"]
                filter_id = data["result"][0]["filter"]["id"]
                # Delete the rule
                response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules/{rule_id}", headers=headers)
                write_debug_file(argv[0], f"Delete Rule Response: {response}")
                handle_api_error(response, "delete rule")
                # Delete the filter
                response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/filters/{filter_id}", headers=headers)
                write_debug_file(argv[0], f"Delete Filter Response: {response}")
                if handle_api_error(response, "delete filter"):
                    #log_message("IP removed from null route successfully")
                    write_debug_file(argv[0], "IP removed from null route successfully")
                    sys.exit(0)
            else:
                write_debug_file(argv[0], "No matching rule found for deletion")
                sys.exit(1)

        """ End Custom Action Delete """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)