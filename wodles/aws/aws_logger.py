#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module implements the AWSLogStrategy class"""

import logging

# Local Imports
from wodles.shared.wazuh_cloud_logger import WazuhLogStrategy

########################################################################################################################
# Classes
########################################################################################################################


class AWSLogStrategy(WazuhLogStrategy):
    """
    AWSLogStrategy class for AWS integration.

    Implements the LogStrategy interface to log messages for AWS integration.
    """

    def __init__(self):
        """
        Initialize the AWSLogStrategy class.

        """
        self.logger = logging.getLogger(':aws-s3')

    def info(self, message: str):
        """
        Log an INFO level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.info("aws.py: info: " + message)

    def debug(self, message: str):
        """
        Log a DEBUG level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.debug("aws.py: debug: " + message)

    def warning(self, message: str):
        """
        Log a WARNING level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.warning("aws.py: warning: " + message)

    def error(self, message: str):
        """
        Log an ERROR level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.error("aws.py: error: " + message)

    def critical(self, message: str):
        """
        Log a CRITICAL level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.critical("aws.py: critical: " + message)
