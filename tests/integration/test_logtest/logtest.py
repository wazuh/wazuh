# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re


# Callbacks

def callback_logtest_started(line):
    match = re.match(r'.*INFO: \(\d+\): Logtest started', line)
    if match:
        return True
    return None


def callback_logtest_disabled(line):
    match = re.match(r'.*INFO: \(\d+\): Logtest disabled', line)
    if match:
        return True
    return None


def callback_configuration_error(line):
    match = re.match(r'.*ERROR: \(\d+\): Invalid value for element', line)
    if match:
        return True
    return None


def callback_session_initialized(line):
    match = re.match(r".*\(7202\): Session initialized with token '(\w{8})'", line)
    if match:
        return match.group(1)
    return None


def callback_remove_session(line):
    match = re.match(r".*\(7206\): The session '(\w{8})' was closed successfully", line)
    if match:
        return match.group(1)
    return None


def callback_invalid_token(line):
    match = re.match(r".*\(7309\): '(\S+)' is not a valid token", line)
    if match:
        return match.group(1)
    return None
