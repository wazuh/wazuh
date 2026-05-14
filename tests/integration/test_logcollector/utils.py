"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from os.path import join as path_join


from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

def build_tc_config(tc_conf_list):
    '''
    Build the configuration for each test case.

    Args:
        tc_conf_list (list): List of test case localfile configurations.

    Returns:
        list: List of configurations for each test case.
    '''

    config_list = []  # List of configurations for each test case

    # Build the configuration for each test case
    for tc_config in tc_conf_list:
        sections = []
        # Build the configuration for each localfile
        for i, elements in enumerate(tc_config, start=1):
            section = {
                "section": "localfile",
                "attributes": [{"unique_id": str(i)}],  # Prevents duplicated localfiles sections
                "elements": elements
            }
            sections.append(section)

        config_list.append({"sections": sections})

    return config_list


def assert_list_logs(regex_messages: list):
    '''
    Asserts if the expected messages are present in the log file in the expected order.

    Args:
        regex_messages (list): List of regular expressions to search in the log file.
    '''

    def get_epoch_timestamp(log):
        '''
        Get the timestamp of the log message in epoch format.

        Args:
            log (str): Log message.

        Returns:
            int: Timestamp of the log message.
        '''
        from datetime import datetime

        date_str = log.split(' ')[0] + ' ' + log.split(' ')[1]
        return int(datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S').timestamp())


    # Monitor the ossec.log file
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    last_log_timestamp = 0

    for regex in regex_messages:
        log_monitor.start(callback=callbacks.generate_callback(regex))
        assert (log_monitor.callback_result != None), f'Did not receive the expected messages in the log file. Expected: {regex}'

        log_timestamp = get_epoch_timestamp(log_monitor.callback_result)
        assert (log_timestamp >= last_log_timestamp), f'The logs are not in the expected order. Expected: {regex}'
        last_log_timestamp = log_timestamp

def assert_not_list_logs(regex_messages: list):
    '''
    Asserts if the expected messages are not present in the log file, the timeout is set to 0.

    The function will return an assertion error if the expected messages are found in the log file.
    The function dont wait for the messages to appear in the log file, reads the current content of the file.
    
    Args:
        regex_messages (list): List of regular expressions to search in the log file.
    '''

    # Monitor the ossec.log file
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    for regex in regex_messages:
        log_monitor.start(callback=callbacks.generate_callback(regex), timeout=0)
        assert (log_monitor.callback_result == None), f'Received the expected messages in the log file. Expected: {regex}'

# Journal functions
def send_log_to_journal(conf_message: dict):
    '''
    Send a log message to the journal.

    This function sends a log message to the journal using the 'logger' command to avoid use third-party libraries.
    Args:
        conf_message (dic): The message to send to the journal, with the following fields:
            - message (str): The message to send to the journal.
            - tag (str): The tag of the message. Default is 'wazuh-itest'.
            - priority (str): The priority of the message. Default is 'info'.
    '''
    import subprocess as sp

    # Send the log message to the journal
    try:
        tag = conf_message['tag'] if 'tag' in conf_message else 'wazuh-itest'
        priority = conf_message['priority'] if 'priority' in conf_message else 'info'
        message = conf_message['message']
        if not message:
            raise Exception("The message field is required in the configuration.")
        sp.run(['logger', '-t', tag, '-p', priority, message], check=True)
    except sp.CalledProcessError as e:
        raise Exception(f"Error sending log message to journal: {e}")
