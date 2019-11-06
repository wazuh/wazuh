#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import re
import sys
from sqlite3 import connect
from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open

# mock AWS libraries
sys.modules['boto3'] = MagicMock()
sys.modules['botocore'] = MagicMock()

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
# read ossec-init from file in test data path
with open(os.path.join(test_data_path, 'ossec-init.conf')) as f:
    ossec_init = f.read()


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
    with patch(f'aws_s3.{class_.__name__}.get_client'), \
        patch(f'aws_s3.{class_.__name__}.get_sts_client'), \
        patch('aws_s3.open', mock_open(read_data=ossec_init)):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'profile': None, 'iam_role_arn': None, 'bucket': 'test',
                        'only_logs_after': '19700101', 'skip_on_error': True,
                        'account_alias': None, 'prefix': 'test',
                        'delete_file': False, 'aws_organization_id': None,
                        'region': None})

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
    with patch(f'aws_s3.{class_.__name__}.get_client'), \
        patch(f'aws_s3.{class_.__name__}.get_sts_client'), \
        patch('aws_s3.open', mock_open(read_data=ossec_init)):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'aws_profile': None, 'iam_role_arn': None,
                        'only_logs_after': '19700101', 'region': None})

        query_version = ins.db_connector.execute(ins.sql_get_metadata_version)
        metadata_version = query_version.fetchone()[0]

        assert(metadata_version == ins.wazuh_version)


@pytest.mark.parametrize('class_, sql_file, db_name', [
    (aws_s3.AWSCloudTrailBucket, 'schema_cloudtrail_test.sql', 'cloudtrail'),
    (aws_s3.AWSConfigBucket, 'schema_config_test.sql', 'config'),
    (aws_s3.AWSVPCFlowBucket, 'schema_vpcflow_test.sql', 'vpcflow'),
    (aws_s3.AWSCustomBucket, 'schema_custom_test.sql', 'custom'),
    (aws_s3.AWSGuardDutyBucket, 'schema_guardduty_test.sql', 'guardduty'),
])
def test_db_maintenance(class_, sql_file, db_name):
    """
    Checks DB maintenance
    """
    with patch(f'aws_s3.{class_.__name__}.get_client'), \
        patch(f'aws_s3.{class_.__name__}.get_sts_client'), \
        patch('sqlite3.connect', side_effect=get_fake_s3_db(sql_file)), \
        patch('aws_s3.open', mock_open(read_data=ossec_init)):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'profile': None, 'iam_role_arn': None, 'bucket': 'test-bucket',
                        'only_logs_after': '19700101', 'skip_on_error': True,
                        'account_alias': None, 'prefix': '',
                        'delete_file': False, 'aws_organization_id': None,
                        'region': None})

        account_id = '123456789'
        ins.aws_account_id = account_id  # set 'aws_account_id' for custom buckets
        flow_log_id = 'fl-1234'  # set 'flow_log_id' for VPC buckets
        region = 'us-east-1'  # not necessary for custom buckets as GuardDuty
        sql_get_first_log_key = f'SELECT log_key FROM {db_name} ORDER BY log_key ASC LIMIT 1;'
        sql_get_last_log_key = f'SELECT log_key FROM {db_name} ORDER BY log_key DESC LIMIT 1;'
        sql_count = f'SELECT COUNT(*) FROM {db_name};'

        # get oldest log_key before execute maintenance
        query = ins.db_connector.execute(sql_get_first_log_key)
        first_log_key_before = query.fetchone()[0]

        # get newest log_key before execute maintenance
        query = ins.db_connector.execute(sql_get_last_log_key)
        last_log_key_before = query.fetchone()[0]

        # maintenance when retain_db_records is bigger than elements in DB
        if class_.__name__ == 'AWSVPCFlowBucket':
            ins.db_maintenance(aws_account_id=account_id, aws_region=region,
                               flow_log_id=flow_log_id)
        else:
            ins.db_maintenance(aws_account_id=account_id, aws_region=region)
        query = ins.db_connector.execute(sql_count.format(account_id=account_id))
        data = query.fetchone()[0]

        assert(data == 8)

        # maintenance when retain_db_records is smaller than elements in DB
        ins.retain_db_records = 6
        if class_.__name__ == 'AWSVPCFlowBucket':
            ins.db_maintenance(aws_account_id=account_id, aws_region=region,
                               flow_log_id=flow_log_id)
        else:
            ins.db_maintenance(aws_account_id=account_id, aws_region=region)
        query = ins.db_connector.execute(sql_count.format(account_id=account_id))
        data = query.fetchone()[0]

        assert(data == ins.retain_db_records)

        # maintenance when retain_db_records is smaller than elements in DB
        ins.retain_db_records = 3
        if class_.__name__ == 'AWSVPCFlowBucket':
            ins.db_maintenance(aws_account_id=account_id, aws_region=region,
                               flow_log_id=flow_log_id)
        else:
            ins.db_maintenance(aws_account_id=account_id, aws_region=region)
        query = ins.db_connector.execute(sql_count.format(account_id=account_id))
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
