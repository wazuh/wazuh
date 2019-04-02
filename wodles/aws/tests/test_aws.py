#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from sqlite3 import connect
import sys
from unittest import TestCase
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_s3_db(*args, **kwargs):
    s3_db = connect(':memory:')
    cur = s3_db.cursor()
    with open(os.path.join(test_data_path, 'schema_metadata_test.sql')) as f:
        cur.executescript(f.read())

    return s3_db


class TestAWS(TestCase):

    @patch('sqlite3.connect', side_effect=get_fake_s3_db)
    @patch('aws_s3.AWSCloudTrailBucket.get_client')
    def test_metadata_version(self, mocked_method, mocked_db):
        """
        Checks if metadata version has been updated
        """
        ct = aws_s3.AWSCloudTrailBucket(**{'reparse': False, 'access_key': None, 'secret_key': None,
                                    'profile': None, 'iam_role_arn': None, 'bucket': 'test',
                                    'only_logs_after': '19700101', 'skip_on_error': True,
                                    'account_alias': None, 'prefix': 'test',
                                    'delete_file': False, 'aws_organization_id': None})

        query_version = ct.db_connector.execute(ct.sql_get_metadata_version)
        metadata_version = query_version.fetchone()[0]

        assert(metadata_version == ct.wazuh_version)
