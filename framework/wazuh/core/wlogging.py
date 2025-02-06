# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import logging.handlers


class CustomFilter:
    """Define a custom filter to differentiate between log types.
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
    """Define attributes of a Python Wazuh daemon's logger.
    """
    def __init__(self, debug_level: [int, str], logger_name: str = 'wazuh',
                 custom_formatter: callable = None, tag: str = '%(asctime)s %(levelname)s: %(message)s',
                 max_size: int = 0):
        """Constructor.

        Parameters
        ----------
        debug_level : int or str
            Log level.
        logger_name : str
            Name of the logger.
        custom_formatter : callable
            Subclass of logging.Formatter. Allows formatting messages depending on their contents.
        tag : str
            Tag defining logging format.
        """
        self.logger = None
        self.debug_level = debug_level
        self.logger_name = logger_name
        self.default_formatter = logging.Formatter(tag, style='%', datefmt="%Y/%m/%d %H:%M:%S")
        if custom_formatter is None:
            self.custom_formatter = self.default_formatter
        else:
            self.custom_formatter = custom_formatter(style='%', datefmt="%Y/%m/%d %H:%M:%S")

    def setup_logger(self):
        """Prepare a logger with:
        * A stream handler.
        * An additional debug level.

        """
        logger = logging.getLogger(self.logger_name)
        logger.propagate = False
        # configure logger

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
    """Define a custom filter to filter WazuhInternalErrors
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
