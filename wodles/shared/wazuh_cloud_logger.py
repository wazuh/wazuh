#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module implements the strategy pattern to provide a flexible logging solution for Wazuh Cloud Modules."""

from abc import ABC, abstractmethod
import logging
import sys

################################################################################
# Classes
################################################################################


class WazuhLogStrategy(ABC):
    """
    LogStrategy interface.

    Defines the methods that need to be implemented by the concrete classes
    (GCP, AWS, and Azure) for logging.
    """

    @abstractmethod
    def info(self, message: str):
        """
        Log an INFO level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def debug(self, message: str):
        """
        Log a DEBUG level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def warning(self, message: str):
        """
        Log a WARNING level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def error(self, message: str):
        """
        Log an ERROR level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def critical(self, message: str):
        """
        Log a CRITICAL level message.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass


class WazuhCloudLogger:
    """
    WazuhCloudLogger class.

    Provides a flexible logging solution for Wazuh that supports
    GCP, AWS, and Azure integrations using the strategy pattern.
    """

    def __init__(self, strategy: WazuhLogStrategy) -> logging.Logger:
        """
        Initialize the Wazuh Cloud Logger class.

        Parameters
        ----------
        strategy : LogStrategy
            The logging strategy to be used (GCP, AWS, or Azure).
        """
        self.strategy = strategy
        self.logger = self.setup_logger()

    def setup_logger(self) -> logging.Logger:
        """
        Set up the logger.

        Returns
        -------
        logging.Logger
            Configured logger instance.
        """
        logger = self.strategy.logger
        logger.setLevel(logging.INFO)
        handler = self._setup_handler()
        logger.addHandler(handler)
        return logger

    def _setup_handler(self) -> logging.Handler:
        """
        Set up the handler for the logger.

        Returns
        -------
        logging.Handler
            Configured handler instance.
        """
        handler = logging.StreamHandler(sys.stdout)
        formatter = self.strategy.formatter if hasattr(self.strategy,
                                                       'formatter') else '%(name)s - %(levelname)s - %(message)s'
        datefmt = self.strategy.datefmt if hasattr(self.strategy, 'datefmt') else None
        handler.setFormatter(logging.Formatter(formatter, datefmt=datefmt))
        return handler

    def info(self, message: str):
        """
        Log an INFO level message using the selected strategy.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.info(message)

    def debug(self, message: str):
        """
        Log a DEBUG level message using the selected strategy.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.debug(message)

    def warning(self, message: str):
        """
        Log a WARNING level message using the selected strategy.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.warning(message)

    def error(self, message: str):
        """
        Log an ERROR level message using the selected strategy.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.error(message)

    def critical(self, message: str):
        """
        Log a CRITICAL level message using the selected strategy.

        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.critical(message)

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
