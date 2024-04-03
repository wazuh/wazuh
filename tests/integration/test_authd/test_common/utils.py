# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import time

from wazuh_testing.constants.paths.sockets import QUEUE_AGENTS_TIMESTAMP_PATH, QUEUE_DIFF_PATH, QUEUE_RIDS_PATH
from wazuh_testing.utils.file import truncate_file, remove_file, recursive_directory_creation


def clean_diff():
    try:
        remove_file(QUEUE_DIFF_PATH)
        recursive_directory_creation(QUEUE_DIFF_PATH)
        os.chmod(QUEUE_DIFF_PATH, 0o777)
    except Exception as e:
        print('Failed to delete %s. Reason: %s' % (QUEUE_DIFF_PATH, e))


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


def check_diff(name, expected, timeout=30):
    diff_path = os.path.join(QUEUE_DIFF_PATH, name)
    wait = time.time() + timeout
    while time.time() < wait:
        ret = os.path.exists(diff_path)
        if ret == expected:
            return True
    return False


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


def create_diff(name):
    SIGID = '533'
    diff_folder = os.path.join(QUEUE_DIFF_PATH, name)
    try:
        os.mkdir(diff_folder)
    except IOError:
        raise

    sigid_folder = os.path.join(diff_folder, SIGID)
    try:
        os.mkdir(sigid_folder)
    except IOError:
        raise

    last_entry_path = os.path.join(sigid_folder, 'last-entry')
    try:
        file = open(last_entry_path, 'w')
        file.close()
        os.chmod(last_entry_path, 0o777)
    except IOError:
        raise
