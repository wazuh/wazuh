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
# Instructions: 
# Before using this create a Rule in Custom Rules:
# hostname: Set the hostname(s) using eq or in (for multiple hosts)
# Description: "Managed via Wazuh"
#
# If USing Gchat set the GCHAT_WEBHOOK_URL, else remove/replace the block for GCHAT notifications


import os
import sys
import re
import json
import requests
import datetime
from pathlib import PureWindowsPath, PurePosixPath

# Define a mapping of agent names to Cloudflare Zone IDs and Domains
agent_mapping = {
    "development": {
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

# Create a function to update the expression
def update_ip_to_expression(expression, hostname, ip):
    # Split the expression into its parts
    parts = expression.split(" or ")
    updated_parts = []

    for part in parts:
        if f"http.host eq \"{hostname}\"" in part:
            # If the hostname matches, add the new IP to the existing IPs
            existing_ips = part.split(" in {")[1].strip("})")
            updated_ips = f"{existing_ips} {ip}"
            updated_part = f"(http.host eq \"{hostname}\" and ip.src in {{{updated_ips}}})"
            updated_parts.append(updated_part)
        elif (f"http.host in " in part and f"\"{hostname}\"" in part):
            # If the hostname matches, add the new IP to the existing IPs
            existing_ips = part.split("ip.src in {")[1].strip("})")
            updated_ips = f"{existing_ips} {ip}"
            pattern = r'\(http\.host in \{(.+?)\}' 
            matches = re.search(pattern, part)
            if matches:
                result = matches.group(1)
            updated_part = f"(http.host in {{{result}}} and ip.src in {{{updated_ips}}})"
            updated_parts.append(updated_part)
        else:
            updated_parts.append(part)

    # Join the updated parts with " or "
    updated_expression = " or ".join(updated_parts)
    return updated_expression

# Create a function to remove an IP from the expression
def remove_ip_from_expression(expression, hostname, ip_to_remove):
    # Split the expression into its parts
    parts = expression.split(" or ")
    updated_parts = []

    for part in parts:
        if f"http.host eq \"{hostname}\"" in part:
            # If the hostname matches, remove the specified IP from the existing IPs
            existing_ips = part.split(" in {")[1].strip("})")
            ip_list = existing_ips.split()
            if ip_to_remove in ip_list:
                ip_list.remove(ip_to_remove)
                updated_ips = " ".join(ip_list)
                if updated_ips:
                    updated_part = f"(http.host eq \"{hostname}\" and ip.src in {{{updated_ips}}})"
                    updated_parts.append(updated_part)
            else:
                updated_parts.append(part)
        elif (f"http.host in " in part and f"\"{hostname}\"" in part):
            # If the hostname matches, add the new IP to the existing IPs
            existing_ips = part.split("ip.src in {")[1].strip("})")
            ip_list = existing_ips.split()
            pattern = r'\(http\.host in \{(.+?)\}' 
            matches = re.search(pattern, part)
            if ip_to_remove in ip_list:
                ip_list.remove(ip_to_remove)
                updated_ips = " ".join(ip_list)
                if updated_ips:
                    result = matches.group(1)
                    updated_part = f"(http.host in {{{result}}} and ip.src in {{{updated_ips}}})"
                    updated_parts.append(updated_part)
        else:
            updated_parts.append(part)

    # Join the updated parts with " or "
    updated_expression = " or ".join(updated_parts)
    return updated_expression

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
    TOKEN = 'CF_TOKEN'
    MODE = 'block'  # block or challenge
    webhook_url = 'GCHAT_WEBHOOK_URL'


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
        params = {
            "action": MODE,
            "description": "Managed via Wazuh"
        }
        
        try:
            get_rule_response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules", headers=headers, params=params)
            if get_rule_response.status_code == 200:
                data = get_rule_response.json()
                if data.get("result"):
                    existing_rule = data['result'][0]
                    # Extract the existing expression and description
                    existing_filter_id = existing_rule['filter']['id']
                    existing_expression = existing_rule['filter']['expression']
                    existing_description = existing_rule['description']
                    

                    # Update the expression
                    updated_expression = update_ip_to_expression(existing_expression, domain, ip)
                    write_debug_file(argv[0], existing_expression)
                    # Create the update payload
                    update_data = {
                        "id": existing_filter_id,
                        "expression": updated_expression,
                        "description": "Managed via Wazuh"
                    }
                    update_rule_response = requests.put(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/filters/{existing_filter_id}", headers=headers, json=update_data)
                    write_debug_file(argv[0], str(update_data))
                    if update_rule_response.status_code == 200:
                        write_debug_file(argv[0], "IP updated to null route successfully")
                        # Create a card message using the provided format
                        card_message = {
                            "cardsV2": [
                                {
                                    "cardId": "unique-card-id",
                                    "card": {
                                        "header": {
                                            "title": "Wazuh XDR - Cloudflare",
                                            "imageUrl": "https://upload.wikimedia.org/wikipedia/commons/1/13/Wazuh-orig.png",
                                            "imageType": "CIRCLE",
                                            "imageAltText": "Avatar for Sasha",
                                        },
                                        "sections": [
                                            {
                                                "header": "IP Block Alert",
                                                "collapsible": False,
                                                "uncollapsibleWidgetsCount": 1,
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://wazuh.com/uploads/2023/08/circle-darkwatchman.png",
                                                            },
                                                            "text": "Agent Name: {}".format(agent_name),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn.icon-icons.com/icons2/2407/PNG/512/cloudflare_icon_146206.png",
                                                            },
                                                            "text": "Domain: {}".format(domain),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn4.iconfinder.com/data/icons/web-hosting-2-2/32/IP_Blocker-512.png",
                                                            },
                                                            "text": "IP Blocked: {}".format(ip),
                                                        }
                                                    }
                                                ],
                                            },
                                        ],
                                    },
                                }
                            ]
                        }
                        # Send the card as a message to the Google Chat room
                        requests.post(webhook_url, json=card_message)
                    else:
                        # Create a card message using the provided format
                        card_message = {
                            "cardsV2": [
                                {
                                    "cardId": "unique-card-id",
                                    "card": {
                                        "header": {
                                            "title": "Wazuh XDR - Cloudflare",
                                            "imageUrl": "https://upload.wikimedia.org/wikipedia/commons/1/13/Wazuh-orig.png",
                                            "imageType": "CIRCLE",
                                            "imageAltText": "Avatar for Sasha",
                                        },
                                        "sections": [
                                            {
                                                "header": "IP Block Failed",
                                                "collapsible": False,
                                                "uncollapsibleWidgetsCount": 1,
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://wazuh.com/uploads/2023/08/circle-darkwatchman.png",
                                                            },
                                                            "text": "Agent Name: {}".format(agent_name),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn.icon-icons.com/icons2/2407/PNG/512/cloudflare_icon_146206.png",
                                                            },
                                                            "text": "Domain: {}".format(domain),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn4.iconfinder.com/data/icons/web-hosting-2-2/32/IP_Blocker-512.png",
                                                            },
                                                            "text": "IP Blocked: {}".format(ip),
                                                        }
                                                    }
                                                ],
                                            },
                                        ],
                                    },
                                }
                            ]
                        }
                        # Send the card as a message to the Google Chat room
                        requests.post(webhook_url, json=card_message)
                        write_debug_file(argv[0], "Adding Filter Failed")
                        write_debug_file(argv[0], str(update_rule_response.text))
                    sys.exit(0)
            else:
                write_debug_file(argv[0], "Rule Fetch Failed.")
            sys.exit(0)
 
        except requests.exceptions.RequestException as e:
            # This exception will catch various request-related issues, including network errors
            write_debug_file(argv[0], f"Request failed: {e}")
        except Exception as e:
            # This will catch other unexpected exceptions
            write_debug_file(argv[0], f"An unexpected error occurred: {e}")

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
            "description": "Managed via Wazuh"
        }

        try:
            get_rule_response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules", headers=headers, params=params)
            if get_rule_response.status_code == 200:
                data = get_rule_response.json()
                if data.get("result"):
                    existing_rule = data['result'][0]
                    # Extract the existing expression and description
                    existing_filter_id = existing_rule['filter']['id']
                    existing_expression = existing_rule['filter']['expression']
                    existing_description = existing_rule['description']
                
                    # Update the expression
                    updated_expression = remove_ip_from_expression(existing_expression, domain, ip)

                    # Create the update payload
                    update_data = {
                        "id": existing_filter_id,
                        "expression": updated_expression,
                        "description": existing_description
                    }
                    update_rule_response = requests.put(f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/filters/{existing_filter_id}", headers=headers, json=update_data)
                    write_debug_file(argv[0], str(updated_expression))
                    if update_rule_response.status_code == 200:
                        write_debug_file(argv[0], "IP removed from Filter deletion")
                        card_message = {
                            "cardsV2": [
                                {
                                    "cardId": "unique-card-id",
                                    "card": {
                                        "header": {
                                            "title": "Wazuh XDR - Cloudflare",
                                            "imageUrl": "https://upload.wikimedia.org/wikipedia/commons/1/13/Wazuh-orig.png",
                                            "imageType": "CIRCLE",
                                            "imageAltText": "Avatar for Sasha",
                                        },
                                        "sections": [
                                            {
                                                "header": "IP UnBlock Alert",
                                                "collapsible": False,
                                                "uncollapsibleWidgetsCount": 1,
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://wazuh.com/uploads/2023/08/circle-darkwatchman.png",
                                                            },
                                                            "text": "Agent Name: {}".format(agent_name),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn.icon-icons.com/icons2/2407/PNG/512/cloudflare_icon_146206.png",
                                                            },
                                                            "text": "Domain: {}".format(domain),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn4.iconfinder.com/data/icons/web-hosting-2-2/32/IP_Blocker-512.png",
                                                            },
                                                            "text": "IP UnBlocked: {}".format(ip),
                                                        }
                                                    }
                                                ],
                                            },
                                        ],
                                    },
                                }
                            ]
                        }
                        requests.post(webhook_url, json=card_message)
                    else:
                        card_message = {
                            "cardsV2": [
                                {
                                    "cardId": "unique-card-id",
                                    "card": {
                                        "header": {
                                            "title": "Wazuh XDR - Cloudflare",
                                            "imageUrl": "https://upload.wikimedia.org/wikipedia/commons/1/13/Wazuh-orig.png",
                                            "imageType": "CIRCLE",
                                            "imageAltText": "Avatar for Sasha",
                                        },
                                        "sections": [
                                            {
                                                "header": "IP UnBlock Failed",
                                                "collapsible": False,
                                                "uncollapsibleWidgetsCount": 1,
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://wazuh.com/uploads/2023/08/circle-darkwatchman.png",
                                                            },
                                                            "text": "Agent Name: {}".format(agent_name),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn.icon-icons.com/icons2/2407/PNG/512/cloudflare_icon_146206.png",
                                                            },
                                                            "text": "Domain: {}".format(domain),
                                                        }
                                                    },
                                                    {
                                                        "decoratedText": {
                                                            "startIcon": {
                                                                "iconUrl": "https://cdn4.iconfinder.com/data/icons/web-hosting-2-2/32/IP_Blocker-512.png",
                                                            },
                                                            "text": "IP UnBlocked: {}".format(ip),
                                                        }
                                                    }
                                                ],
                                            },
                                        ],
                                    },
                                }
                            ]
                        }
                        requests.post(webhook_url, json=card_message)
                    sys.exit(0)
            else:
                write_debug_file(argv[0], "No matching rule found for deletion")
                sys.exit(1)

        except requests.exceptions.RequestException as e:
            # This exception will catch various request-related issues, including network errors
            write_debug_file(argv[0], f"Get rule request failed: {e}")
        except requests.exceptions.HTTPError as e:
            # This exception will catch HTTP errors (4xx and 5xx status codes)
            write_debug_file(argv[0], f"Get rule failed: {e}")
        except Exception as e:
            # This will catch other unexpected exceptions
            write_debug_file(argv[0], f"Get rule failed with unknown error: {e}")

        """ End Custom Action Delete """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)