#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module implements a logging solution for Wazuh Cloud Modules."""

import logging
import sys


class WazuhCloudLogger:
    """
    WazuhCloudLogger class.
    Provides a standardized logging solution for Wazuh.
    """

    def __init__(self, logger_name: str):
        """
        Initialize the Wazuh Cloud Logger class.
        Parameters
        ----------
        logger_name : str
            The logging name to be used.
        """
        self.logger_name = logger_name
        self.logger = self.setup_logger()

    def setup_logger(self) -> logging.Logger:
        """
        Set up the logger.
        Returns
        -------
        logging.Logger
            Configured logger instance.
        """
        logger = logging.getLogger(self.logger_name)
        logger.setLevel(logging.INFO)
        handler = self._setup_handler()
        logger.addHandler(handler)
        return logger

    @staticmethod
    def _setup_handler() -> logging.Handler:
        """
        Set up the handler for the logger.
        Returns
        -------
        logging.Handler
            Configured handler instance.
        """
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
        return handler

    def info(self, message: str):
        """
        Log an INFO level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.info(message)

    def debug(self, message: str):
        """
        Log a DEBUG level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.debug(message)

    def warning(self, message: str):
        """
        Log a WARNING level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.logger.warning(message)

    def error(self, message: str, log_exception: bool = False):
        """
        Log an ERROR level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        log_exception : bool
            A boolean to log more information about the exception
        """
        self.logger.error(message,
                          exc_info=log_exception)

    def set_level(self, log_level: int):
        """
        Set the logging level for the logger used by the strategy.
        Parameters
        ----------
        log_level : int
            The logging level to be set.
        """
        logger_level = logging.DEBUG if log_level == 2 else logging.INFO
        self.logger.setLevel(logger_level)
