#!/usr/bin/env python3
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
import sys
import time
import os

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ModuleNotFoundError as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# ADD THIS TO ossec.conf configuration:
#  <integration>
#      <name>shuffle</name>
#      <hook_url>http://<IP>:3001/api/v1/hooks/<HOOK_ID></hook_url>
#      <level>3</level>
#      <alert_format>json</alert_format>
#  </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
SKIP_RULE_IDS = ["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932",
                 "80710", "87929", "87928", "5710"]

# Set paths
LOG_FILE = f'{pwd}/logs/integrations.log'


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                now,
                args[1],
                args[2],
                args[3],
                args[4] if len(args) > 4 else '',
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

        # Main function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args):
    debug("# Starting")

    # Read args
    alert_file_location = args[1]
    webhook: str = args[3]

    debug("# Webhook")
    debug(webhook)

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except FileNotFoundError:
        debug("# Alert file %s doesn't exist" % alert_file_location)
        sys.exit(3)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting json_alert %s" % e)
        sys.exit(4)

    debug("# Processing alert")
    debug(json_alert)

    debug("# Generating message")
    msg: str = generate_msg(json_alert)

    # Check if alert is skipped
    if isinstance(msg, str):
        if not msg:
            return

    debug(msg)

    debug("# Sending message")

    send_msg(msg, webhook)


def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg)


# Skips container kills to stop self-recursion
def filter_msg(alert) -> bool:
    # SKIP_RULE_IDS need to be filtered because Shuffle starts Docker containers, therefore those alerts are triggered

    return not alert["rule"]["id"] in SKIP_RULE_IDS


def generate_msg(alert) -> str:
    if not filter_msg(alert):
        print("Skipping rule %s" % alert["rule"]["id"])
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

    return json.dumps(msg)


def send_msg(msg: str, url: str):
    debug("# In send msg")
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, verify=False)
    debug("# After send msg: %s" % res)


if __name__ == "__main__":
    main(sys.argv)
