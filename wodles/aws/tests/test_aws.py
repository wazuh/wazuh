#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
import sys
from unittest import TestCase
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
from aws_s3 import WazuhIntegration

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_s3_data(*args, **kwargs):
    s3_db = sqlite3.connect(':memory:')
    try:
        cur = s3_db.cursor()
        query = 'SELECT * FROM metadata;'
        with open(os.path.join(test_data_path, 'schema_metadata_test.sql')) as f:
            cur.executescript(f.read())
        #s3_db.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        rows = s3_db.execute(query).fetchall()
        if len(rows) > 0 and 'COUNT(*)' in rows[0]:
            return rows[0]['COUNT(*)']
        return rows
    finally:
        s3_db.close()


class TestAWS(TestCase):

    @patch('WazuhIntegration.client')
    def test_get_metadata_version(self):
        """
        Checks metadata version
        """
        with patch('WazuhIntegration.db_connector') as mock_db:
            #wi = WazuhIntegration(access_key, secret_key, aws_profile, iam_role_arn,
            #    service_name=None, region=None, bucket=None)
            wi = WazuhIntegration(None, None, None, None,
                service_name=None, region=None, bucket=None)
            wi.check_metadata_version()
