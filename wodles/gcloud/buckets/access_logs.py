#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains the Class for getting Google Cloud Storage Access logs"""

import csv
import logging
from os.path import dirname, realpath
from sys import path

path.append(dirname(realpath(__file__)))  # noqa: E501
from bucket import WazuhGCloudBucket
from wodles.shared.wazuh_cloud_logger import WazuhCloudLogger

################################################################################
# Classes
################################################################################


class GCSAccessLogs(WazuhGCloudBucket):
    """Class for getting Google Cloud Storage Access Logs logs"""
    def __init__(self, credentials_file: str, logger: WazuhCloudLogger, **kwargs):
        """Class constructor.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file.
        logger : WazuhCloudLogger
            Logger to use.
        kwargs : any
            Additional named arguments for WazuhGCloudBucket.
        """
        super().__init__(credentials_file, logger, **kwargs)
        self.db_table_name = "access_logs"

    def load_information_from_file(self, msg: str):
        """Load the contents of an Access Logs blob and process them.

        GCS Access Logs blobs will always contain the fieldnames as the first line while the remaining lines store the
        data of the log itself.

        Parameters
        ----------
        msg : str
            A string with the contents of the blob file.

        Returns
        -------
        list
            A list of JSON formatted events.
        """
        # Clean and split each line in the file
        lines = msg.replace('"', '').split("\n")

        # Get the fieldnames from the first line
        fieldnames = [field.strip() for field in lines[0].split(",")]
        values = lines[1:]
        tsv_file = csv.DictReader(values, fieldnames=fieldnames, delimiter=',')
        return [dict(x, source='gcp_bucket') for x in tsv_file]
