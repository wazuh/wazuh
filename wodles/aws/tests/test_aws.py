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
from aws_s3 import AWSCloudTrailBucket

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_s3_db(*args, **kwargs):
    s3_db = sqlite3.connect(':memory:')
    #cur = s3_db.cursor()
    with open(os.path.join(test_data_path, 'schema_metadata_test.sql')) as f:
        cur.executescript(f.read())
    #s3_db.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    return s3_db


class TestAWS(TestCase):

    @patch.object(AWSCloudTrailBucket, 'get_client')
    def test_get_metadata_version(self, mocked_method):
        """
        Checks metadata version
        """
        #with patch('aws_s3.WazuhIntegration') as mock_db:
            #wi = WazuhIntegration(access_key, secret_key, aws_profile, iam_role_arn,
            #    service_name=None, region=None, bucket=None)
        #mocked_method.return_value = None

        with patch.object(sqlite3, 'connect', side_effect=get_fake_s3_db) as mock_db:
            wi = AWSCloudTrailBucket(**{'reparse': False, 'access_key': None, 'secret_key': None,
                                  'profile': None, 'iam_role_arn': None, 'bucket': 'test',
                                  'only_logs_after': '19700101', 'skip_on_error': True,
                                  'account_alias': None, 'prefix': 'test',
                                  'delete_file': False, 'aws_organization_id': None})
            wi.check_metadata_version()
