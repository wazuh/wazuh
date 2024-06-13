# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import calendar
import glob
import gzip
import logging
import logging.handlers
import os
import re
import shutil
from datetime import date

from wazuh.core import common, utils


class TimeBasedFileRotatingHandler(logging.handlers.TimedRotatingFileHandler):
    """
    Wazuh log rotation. It rotates the log at midnight and sets the appropriate permissions to the new log file.
    """

    def doRollover(self):
        """Override base class method to make the set the appropriate permissions to the new log file."""
        # Rotate the file first
        logging.handlers.TimedRotatingFileHandler.doRollover(self)

        # Save rotated file in {WAZUH_PATH}/logs/api directory
        rotated_file = glob.glob("{}.*".format(self.baseFilename))[0]

        new_rotated_file = self.compute_log_directory(rotated_file)
        with open(rotated_file, 'rb') as f_in, gzip.open(new_rotated_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.chmod(new_rotated_file, 0o640)
        os.unlink(rotated_file)

    def compute_log_directory(self, rotated_filepath: str):
        """Based on the name of the rotated file, compute in which directory it should be stored.

        Parameters
        ----------
        rotated_filepath : str
            Filepath of the rotated log.

        Returns
        -------
        str
            New directory path.
        """
        rotated_file = os.path.basename(rotated_filepath)
        year, month, day = re.match(r'[\w.]+\.(\d+)-(\d+)-(\d+)', rotated_file).groups()
        month = calendar.month_abbr[int(month)]
        log_path = os.path.join(os.path.splitext(self.baseFilename)[0], year, month)
        if not os.path.exists(log_path):
            utils.mkdir_with_mode(log_path, 0o750)

        return os.path.join(log_path, f"{os.path.basename(self.baseFilename)}-{day}.gz")


class SizeBasedFileRotatingHandler(logging.handlers.RotatingFileHandler):
    """Wazuh log rotation. It rotates when the logging file size exceeds the maximum number of bytes configured."""

    def doRollover(self):
        """Override base class method to make the set the appropriate permissions to the new log file.'"""
        # Rotate the file first
        logging.handlers.RotatingFileHandler.doRollover(self)

        # Save rotated file in {WAZUH_PATH}/logs/api directory
        rotated_file = glob.glob("{}.*".format(self.baseFilename))[0]

        new_rotated_file = self.compute_log_directory()
        with open(rotated_file, 'rb') as f_in, gzip.open(new_rotated_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.chmod(new_rotated_file, 0o640)
        os.unlink(rotated_file)

    def compute_log_directory(self):
        """Based on the current date and iteration of the rotated file, compute in which directory it should be stored.

        Returns
        -------
        New directory path.
        """
        today = date.today()
        year, month, day = today.year, today.month, f"{today.day:02d}"
        month = calendar.month_abbr[int(month)]
        iteration = 1

        log_path = os.path.join(os.path.splitext(self.baseFilename)[0], str(year), month)
        if not os.path.exists(log_path):
            utils.mkdir_with_mode(log_path, 0o750)

        while os.path.exists(os.path.join(log_path, f"{os.path.basename(self.baseFilename)}-{day}_{iteration}.gz")):
            iteration += 1

        return os.path.join(log_path, f"{os.path.basename(self.baseFilename)}-{day}_{iteration}.gz")


class CustomFilter:
    """
    Define a custom filter to differentiate between log types.
    """

    def __init__(self, log_type: str):
        """Constructor.

        Parameters
        ----------
        log_type : str
            Value used to specify the log type of the related log handler.
        """
        self.log_type = log_type

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter the log entry depending on its log type.

        Parameters
        ----------
        record : logging.LogRecord
            Contains all the information to the event being logged.

        Returns
        -------
        bool
            Boolean used to determine if the log entry should be logged.
        """
        # If the log file is not specifically filtered, then it should log into both files
        return True if not hasattr(record, 'log_type') or record.log_type == self.log_type else False


class WazuhLogger:
    """
    Define attributes of a Python Wazuh daemon's logger.
    """
    def __init__(self, foreground_mode: bool, log_path: str, debug_level: [int, str], logger_name: str = 'wazuh',
                 custom_formatter: callable = None, tag: str = '%(asctime)s %(levelname)s: %(message)s',
                 max_size: int = 0):
        """Constructor.

        Parameters
        ----------
        foreground_mode : bool
            Enable stream handler on sys.stderr.
        log_path : str
            Filepath of the file to send logs to. Relative to the Wazuh installation path.
        debug_level : int or str
            Log level.
        logger_name : str
            Name of the logger.
        custom_formatter : callable
            Subclass of logging.Formatter. Allows formatting messages depending on their contents.
        tag : str
            Tag defining logging format.
        max_size : int
            Number of bytes the log can store at max. Once reached, the log will be rotated.
        """
        self.log_path = os.path.join(common.WAZUH_PATH, log_path)
        self.logger = None
        self.foreground_mode = foreground_mode
        self.debug_level = debug_level
        self.logger_name = logger_name
        self.default_formatter = logging.Formatter(tag, style='%', datefmt="%Y/%m/%d %H:%M:%S")
        if custom_formatter is None:
            self.custom_formatter = self.default_formatter
        else:
            self.custom_formatter = custom_formatter(style='%', datefmt="%Y/%m/%d %H:%M:%S")
        self.max_size = max_size

    def setup_logger(self, handler: logging.Handler = None):
        """
        Prepare a logger with:
            * Two rotating file handlers (time | size).
            * A stream handler (if foreground_mode is enabled).
            * An additional debug level.

        :param handler: custom handler that can be set instead of the default one.
        """
        logger = logging.getLogger(self.logger_name)
        cf = CustomFilter('log') if self.log_path.endswith('.log') else CustomFilter('json')
        logger.propagate = False
        # configure logger
        if handler:
            custom_handler = handler
        else:
            custom_handler = TimeBasedFileRotatingHandler(filename=self.log_path, when='midnight') if self.max_size == 0 \
            else SizeBasedFileRotatingHandler(filename=self.log_path, maxBytes=self.max_size, backupCount=1)

        custom_handler.setFormatter(self.custom_formatter)
        custom_handler.addFilter(cf)
        logger.addHandler(custom_handler)

        if self.foreground_mode:
            ch = logging.StreamHandler()
            ch.setFormatter(self.default_formatter)
            ch.addFilter(CustomFilter('log'))
            logger.addHandler(ch)

        # add a new debug level
        logging.DEBUG2 = 5

        def debug2(self, message, *args, **kws):
            if self.isEnabledFor(logging.DEBUG2):
                self._log(logging.DEBUG2, message, args, **kws)

        def error(self, msg, *args, **kws):
            if self.isEnabledFor(logging.ERROR):
                if 'exc_info' not in kws:
                    kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
                self._log(logging.ERROR, msg, args, **kws)

        logging.addLevelName(logging.DEBUG2, "DEBUG2")

        logging.Logger.debug2 = debug2
        logging.Logger.error = error

        self.logger = logger

    def __getattr__(self, item: str) -> object:
        """Overwrite __getattr__ magic method.
            * If the item requested is an attribute of self.logger, return it.
            * If it's an attribute of self, return it.
            * Otherwise, raise an AttributeError exception

        Parameters
        ----------
        item : str
            Name of the attribute to return.

        Returns
        -------
        object
            Attribute named "item".
        """
        if hasattr(self.logger, item):
            return getattr(self.logger, item)
        elif item in vars(self):
            return getattr(self, item, None)
        else:
            raise AttributeError(f"{self.__class__.__name__} object has no attribute {item}")


class CLIFilter(logging.Filter):
    """
    Define a custom filter to filter WazuhInternalErrors
    """

    messages_to_avoid = ['Wazuh Internal Error', 'WazuhInternalError']

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter the log entry depending on its message contents.

        Parameters
        ----------
        record : logging.LogRecord
            Contains the information of the event being logged.

        Returns
        -------
        bool
            Whether the log entry should be logged or not.
        """
        for msg_to_avoid in self.messages_to_avoid:
            if msg_to_avoid in record.getMessage():
                return False
        return True
