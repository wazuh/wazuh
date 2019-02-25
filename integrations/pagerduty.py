#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# February 25, 2019.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import argparse
import json
import os
import requests
import sys
import time


debug_enabled = False
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = f'{pwd}/logs/integrations.log'


def get_args():
    """
    Gets input parameters.
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-a', '--alert-file', dest='alert_file_location', help='Input log file',
                        required=True, action='store', default=None)
    parser.add_argument('-k', '--api-key', dest='api_key', help='API key', required=True,
                        action='store', default=None)
    parser.add_argument('-d', '--debug', dest='debug', help='Debug',
                        action='store_true', default=False)
    parser.add_argument('-u', '--hook-url', dest='hook_url', help='Webhook URL',
                        action='store_false', default=False)

    return parser.parse_args()


def send_request(payload):
    """
    Sends request to PagerDuty
    :param payload: Payload to be send
    :return: None
    """
    url = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'
    headers = {'Content-Type: application/json'}
    requests.post(url, data=payload, headers=headers)


def debug(msg):
    if debug_enabled:
        msg = f'{now}: {msg}\n'

        print(msg)

        f = open(log_file, 'a')
        f.write(msg)
        f.close()


def main(args):
    debug("# Starting")

    # Read args
    alert_file_location = args.alert_file_location
    api_key = args.api_key

    debug("# API Key")
    debug(api_key)

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)

    debug("# Processing alert")
    debug(json_alert)

    payload = ({"service_key": api_key,
               "incident_key": f"Alert: {json_alert.get('timestamp', '')} / Rule: {json_alert.get('rule', {}).get('id', '')}",
               "event_type": "trigger",
               "description": f"OSSEC Alert: {json_alert.get('rule', {}).get('description', '')}",
               "client": "OSSEC IDS", "client_url": "http://dcid.me/ossec",
               "details":
                   {"location": f"{json_alert.get('location', '')}",
                    "Rule": f"{json_alert.get('rule', {}).get('id', '')}",
                    "Description": f"{json_alert.get('rule', {}).get('description', '')}",
                    "Log": f"{json_alert.get('full_log', '')}"
                   }
              })

    send_request(json.loads(payload))


if __name__ == '__main__':
    try:
        # Read arguments
        args = get_args()

        bad_arguments = False
        if len(sys.argv) >= 4 and args.alert_file_location is not None \
            and args.api_key is not None:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2],
                                               sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = True if args.debug is True else False
        else:
            msg = f'{now} Wrong arguments'
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(args)

    except Exception as e:
        debug(str(e))
        raise
