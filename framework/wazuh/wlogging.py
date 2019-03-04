# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import logging.handlers
import os
from wazuh import common, utils
import glob
import gzip
import shutil
import re
import calendar


class CustomFileRotatingHandler(logging.handlers.TimedRotatingFileHandler):
    """
    Wazuh cluster log rotation. It rotates the log at midnight and sets the appropiate permissions to the new log file.
    Also, rotated logs are stored in /logs/ossec
    """

    def doRollover(self):
        """
        Override base class method to make the set the appropiate permissions to the new log file
        """
        # Rotate the file first
        logging.handlers.TimedRotatingFileHandler.doRollover(self)

        # Set appropiate permissions
        #os.chown(self.baseFilename, common.ossec_uid, common.ossec_gid)
        #os.chmod(self.baseFilename, 0o660)

        # Save rotated file in /logs/ossec directory
        rotated_file = glob.glob("{}.*".format(self.baseFilename))[0]

        new_rotated_file = self.computeArchivesDirectory(rotated_file)
        with open(rotated_file, 'rb') as f_in, gzip.open(new_rotated_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.chmod(new_rotated_file, 0o640)
        os.unlink(rotated_file)

    def computeArchivesDirectory(self, rotated_filepath):
        """
        Based on the name of the rotated file, compute in which directory it should be stored.

        :param rotated_filepath: Filepath of the rotated log
        :return: New directory path
        """
        rotated_file = os.path.basename(rotated_filepath)
        year, month, day = re.match(r'[\w\.]+\.(\d+)-(\d+)-(\d+)', rotated_file).groups()
        month = calendar.month_abbr[int(month)]

        log_path = os.path.join(self.baseFilename.replace('.log', ''), year, month)
        if not os.path.exists(log_path):
            utils.mkdir_with_mode(log_path, 0o750)

        return '{}/cluster-{}.log.gz'.format(log_path, day)


class WazuhLogger:
    """
    Defines attributes of a Python wazuh daemon's logger
    """
    def __init__(self, foreground_mode: bool, log_path: str, tag: str, debug_level: [int, str]):
        self.log_path = os.path.join(common.ossec_path, log_path)
        self.tag = tag
        self.logger = None
        self.foreground_mode = foreground_mode
        self.debug_level = debug_level

    def setup_logger(self):
        logger = logging.getLogger('wazuh')
        logger.propagate = False
        # configure logger
        fh = CustomFileRotatingHandler(filename=self.log_path, when='midnight')
        formatter = logging.Formatter(self.tag)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        if self.foreground_mode:
            ch = logging.StreamHandler()
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        # add a new debug level
        logging.DEBUG2 = 5

        def debug2(self, message, *args, **kws):
            if self.isEnabledFor(logging.DEBUG2):
                self._log(logging.DEBUG2, message, args, **kws)

        def error(self, msg, *args, **kws):
            if self.isEnabledFor(logging.ERROR):
                kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
                self._log(logging.ERROR, msg, args, **kws)

        logging.addLevelName(logging.DEBUG2, "DEBUG2")

        logging.Logger.debug2 = debug2
        logging.Logger.error = error

        self.logger = logger

    def __getattr__(self, item):
        if hasattr(self.logger, item):
            return getattr(self.logger, item)
        elif item in vars(self):
            return getattr(self, item, None)
        else:
            raise AttributeError(f"{self.__class__.__name__} object has no attribute {item}")
