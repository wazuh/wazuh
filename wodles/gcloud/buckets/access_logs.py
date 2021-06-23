#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import csv
import os
import sys

from google.cloud import storage

sys.path.append(os.path.dirname(os.path.realpath(__file__)))  # noqa: E501
from bucket import WazuhGCloudBucket


class GCSAccessLogs(WazuhGCloudBucket):
    def __init__(self, credentials_file: str, logger, **kwargs):
        self.db_table_name = "access_logs"
        WazuhGCloudBucket.__init__(self, credentials_file, logger, **kwargs)

    def load_information_from_file(self, msg):
        # Clean and split each line in the file
        lines = msg.replace('"', '').split("\n")

        # Get the fieldnames from the first line
        # GCS access logs will always contain the fieldnames as the first line
        fieldnames = lines[0].split(",")
        values = lines[1:]
        tsv_file = csv.DictReader(values, fieldnames=fieldnames, delimiter=',')
        return [dict(x, source='gcp_bucket') for x in tsv_file]
