#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains tools for processing events from a Google Cloud subscription."""  # noqa: E501

import logging
import socket
import tools


class WazuhGCloudIntegration:
    """Class for sending events from Google Cloud to Wazuh."""

    header = '1:Wazuh-GCloud:'
    key_name = 'gcp'

    def __init__(self, logger: logging.Logger):
        self.wazuh_queue = tools.get_wazuh_queue()
        self.logger = logger

    def check_permissions(self):
        raise NotImplementedError

    def format_msg(self, msg: str) -> str:
        """Format a message.

        Parameters
        ----------
        msg : str
            Message to be formatted

        Returns
        -------
        A str with the formatted message
        """
        # Insert msg as value of self.key_name key.
        return f'{{"integration": "gcp", "{self.key_name}": {msg}}}'

    def process_data(self):
        raise NotImplementedError

    def send_msg(self, msg: str):
        """Send an event to the Wazuh queue.

        Parameters
        ----------
        msg : str
            Event to be sent
        """
        event_json = f'{self.header}{msg}'.encode(errors='replace')  # noqa: E501
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            self.logger.debug(f'Sending msg to analysisd: "{event_json}"')
            s.send(event_json)
            s.close()
        except socket.error as e:
            if e.errno == 111:
                self.logger.critical('Wazuh must be running')
                raise e
            else:
                self.logger.critical('Error sending event to Wazuh')
                raise e
