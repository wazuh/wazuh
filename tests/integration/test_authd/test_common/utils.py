# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import time

from wazuh_testing.constants.paths.sockets import QUEUE_AGENTS_TIMESTAMP_PATH, QUEUE_RIDS_PATH
from wazuh_testing.utils.file import truncate_file


def clean_rids():
    for filename in os.listdir(QUEUE_RIDS_PATH):
        file_path = os.path.join(QUEUE_RIDS_PATH, filename)
        if "sender_counter" not in file_path:
            try:
                os.unlink(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))


def clean_agents_timestamp():
    truncate_file(QUEUE_AGENTS_TIMESTAMP_PATH)


def check_rids(id, expected):
    agent_info_path = os.path.join(QUEUE_RIDS_PATH, id)
    if expected == os.path.exists(agent_info_path):
        return True
    else:
        return False


def check_agent_timestamp(id, name, ip, expected):
    line = "{} {} {}".format(id, name, ip)
    found = False
    try:
        with open(QUEUE_AGENTS_TIMESTAMP_PATH) as file:
            file_lines = file.read().splitlines()
            for file_line in file_lines:
                if line in file_line:
                    found = True
                    break
    except IOError:
        raise
    if found == expected:
        return True
    else:
        return False


def create_rids(id):
    rids_path = os.path.join(QUEUE_RIDS_PATH, id)
    try:
        file = open(rids_path, 'w')
        file.close()
        os.chmod(rids_path, 0o777)
    except IOError:
        raise


