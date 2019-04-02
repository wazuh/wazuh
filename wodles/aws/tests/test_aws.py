#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import re
import sys
from sqlite3 import connect
from unittest import TestCase
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_s3_db(sql_file):

    def create_memory_db(*args, **kwargs):
        s3_db = connect(':memory:')
        cur = s3_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())

        return s3_db

    return create_memory_db


@pytest.mark.parametrize('class_', [
    aws_s3.AWSCloudTrailBucket,
    aws_s3.AWSConfigBucket,
    aws_s3.AWSVPCFlowBucket,
    aws_s3.AWSCustomBucket,
    aws_s3.AWSGuardDutyBucket,
])
@patch('sqlite3.connect', side_effect=get_fake_s3_db('schema_metadata_test.sql'))
def test_metadata_version_buckets(mocked_db, class_):
    """
    Checks if metadata version has been updated
    """
    with patch(f'aws_s3.{class_.__name__}.get_client'):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'profile': None, 'iam_role_arn': None, 'bucket': 'test',
                        'only_logs_after': '19700101', 'skip_on_error': True,
                        'account_alias': None, 'prefix': 'test',
                        'delete_file': False, 'aws_organization_id': None})

        query_version = ins.db_connector.execute(ins.sql_get_metadata_version)
        metadata_version = query_version.fetchone()[0]

        assert(metadata_version == ins.wazuh_version)


@pytest.mark.parametrize('class_', [
    aws_s3.AWSInspector
])
@patch('sqlite3.connect',  side_effect=get_fake_s3_db('schema_metadata_test.sql'))
def test_metadata_version_services(mocked_db, class_):
    """
    Checks if metadata version has been updated
    """
    with patch(f'aws_s3.{class_.__name__}.get_client'):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'aws_profile': None, 'iam_role_arn': None,
                        'only_logs_after': '19700101', 'region': None})

        query_version = ins.db_connector.execute(ins.sql_get_metadata_version)
        metadata_version = query_version.fetchone()[0]

        assert(metadata_version == ins.wazuh_version)


@pytest.mark.parametrize('class_', [
    aws_s3.AWSCloudTrailBucket,
])
@patch('sqlite3.connect', side_effect=get_fake_s3_db('schema_cloudtrail_test.sql'))
def test_cloudtrail_db_maintenance(mocked_db, class_):
    """
    Checks DB maintenance
    """
    account_id = '123456789'
    region = 'us-east-1'
    sql_get_first_log_key = "SELECT log_key FROM cloudtrail ORDER BY log_key ASC LIMIT 1;"
    sql_get_last_log_key = "SELECT log_key FROM cloudtrail ORDER BY log_key DESC LIMIT 1;"
    sql_count_cloudtrail = "SELECT COUNT(*) FROM cloudtrail WHERE aws_region='{region}' \
                            AND aws_account_id='{account_id}';"

    with patch(f'aws_s3.{class_.__name__}.get_client'):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'profile': None, 'iam_role_arn': None, 'bucket': 'test-bucket',
                        'only_logs_after': '19700101', 'skip_on_error': True,
                        'account_alias': None, 'prefix': '',
                        'delete_file': False, 'aws_organization_id': None})

        # get oldest log_key before execute maintenance
        query = ins.db_connector.execute(sql_get_first_log_key)
        first_log_key_before = query.fetchone()[0]

        # get newest log_key before execute maintenance
        query = ins.db_connector.execute(sql_get_last_log_key)
        last_log_key_before = query.fetchone()[0]

        # maintenance when retain_db_records is bigger than elements in DB
        ins.db_maintenance('123456789', 'us-east-1')
        query = ins.db_connector.execute(sql_count_cloudtrail.format(region=region, \
                                         account_id=account_id))
        data = query.fetchone()[0]

        assert(data == 8)

        # maintenance when retain_db_records is smaller than elements in DB
        ins.retain_db_records = 6
        ins.db_maintenance(account_id, region)
        query = ins.db_connector.execute(sql_count_cloudtrail.format(region=region, \
                                         account_id=account_id))
        data = query.fetchone()[0]

        assert(data == ins.retain_db_records)

        # maintenance when retain_db_records is smaller than elements in DB
        ins.retain_db_records = 3
        ins.db_maintenance(account_id, region)
        query = ins.db_connector.execute(sql_count_cloudtrail.format(region=region, \
                                         account_id=account_id))
        data = query.fetchone()[0]

        assert(data == ins.retain_db_records)

        # get oldest log_key after execute maintenance
        query = ins.db_connector.execute(sql_get_first_log_key)
        first_log_key_after = query.fetchone()[0]

        assert(first_log_key_before < first_log_key_after)

        # get newest log_key after execute maintenance
        query = ins.db_connector.execute(sql_get_last_log_key)
        last_log_key_after = query.fetchone()[0]

        assert(last_log_key_before == last_log_key_after)

