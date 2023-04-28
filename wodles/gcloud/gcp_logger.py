#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module implements the GCPLogStrategy class"""

import logging

# Local Imports
from wodles.shared.wazuh_cloud_logger import WazuhLogStrategy

########################################################################################################################
# Classes
########################################################################################################################


class GCPLogStrategy(WazuhLogStrategy):
    """
    GCPLogStrategy class for GCP integration.

    Implements the LogStrategy interface to log messages for GCP integration.
    """
    def __init__(self):
        """
        Initialize the GCPLogStrategy class.

        Parameters
        ----------
        logger : logging.Logger
            The logger instance.
        """
        self.logger = logging.getLogger(':gcloud_wodle:')

    def info(self, message: str):
        """
        Log an INFO level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.info(message)

    def debug(self, message: str):
        """
        Log an DEBUG level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.debug(message)

    def warning(self, message: str):
        """
        Log an WARNING level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.warning(message)

    def error(self, message: str):
        """
        Log an ERROR level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.error(message)

    def critical(self, message: str):
        """
        Log an CRITICAL level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.critical(message)
