#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import csv
import logging
from os.path import dirname, realpath
from sys import path

path.append(dirname(realpath(__file__)))  # noqa: E501
from bucket import WazuhGCloudBucket


class GCSAccessLogs(WazuhGCloudBucket):
    """Class for getting Google Cloud Storage Access Logs logs"""
    def __init__(self, credentials_file: str, logger: logging.Logger, **kwargs):
        """Class constructor.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file.
        logger : logging.Logger
            Logger to use.
        kwargs : any
            Additional named arguments for WazuhGCloudBucket.
        """
        super().__init__(credentials_file, logger, **kwargs)
        self.db_table_name = "access_logs"

    def load_information_from_file(self, file):
        """Load the contents of an Access Logs blob and process them.

        GCS Access Logs blobs will always contain the fieldnames as the first line while the remaining lines store the
        data of the log itself.

        Parameters
        ----------
        file : iterable of str
            The lines of the blob file.

        Returns
        -------
        generator
            JSON formatted events, yielded one at a time.
        """
        # Clean each line in the file
        lines = (line.replace('"', '') for line in file)

        # Get the fieldnames from the first line
        fieldnames = [field.strip() for field in next(lines, '').split(",")]
        tsv_file = csv.DictReader(lines, fieldnames=fieldnames, delimiter=',')
        return (dict(x, source='gcp_bucket') for x in tsv_file)
