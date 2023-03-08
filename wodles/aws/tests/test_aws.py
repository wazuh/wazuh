#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import io
import os
import sys
import json
from sqlite3 import connect
from unittest.mock import patch, MagicMock
import pytest
from datetime import datetime

# mock AWS libraries
sys.modules['boto3'] = MagicMock()
sys.modules['botocore'] = MagicMock()

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_path = os.path.join(test_data_path, 'log_files')
wazuh_installation_path = '/var/ossec'
wazuh_version = 'WAZUH_VERSION'

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
        patch(f'aws_s3.utils.find_wazuh_path', return_value=wazuh_installation_path), \
        patch(f'aws_s3.utils.get_wazuh_version', return_value=wazuh_version):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'profile': None, 'iam_role_arn': None, 'bucket': 'test',
                        'only_logs_after': '19700101', 'skip_on_error': True,
                        'account_alias': None, 'prefix': 'test',
                        'delete_file': False, 'aws_organization_id': None,
                        'region': None, 'suffix': '', 'discard_field': None,
                        'discard_regex': None, 'sts_endpoint': None, 'service_endpoint': None})

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
        patch(f'aws_s3.utils.find_wazuh_path', return_value=wazuh_installation_path), \
        patch(f'aws_s3.utils.get_wazuh_version', return_value=wazuh_version):
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
        patch(f'aws_s3.utils.find_wazuh_path', return_value=wazuh_installation_path), \
        patch(f'aws_s3.utils.get_wazuh_version', return_value=wazuh_version):
        ins = class_(**{'reparse': False, 'access_key': None, 'secret_key': None,
                        'profile': None, 'iam_role_arn': None, 'bucket': 'test-bucket',
                        'only_logs_after': '19700101', 'skip_on_error': True,
                        'account_alias': None, 'prefix': '',
                        'delete_file': False, 'aws_organization_id': None,
                        'region': None, 'suffix': '', 'discard_field': None,
                        'discard_regex': None, 'sts_endpoint': None, 'service_endpoint': None})

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


@pytest.mark.parametrize('log_key, decompression_function', [
    ('test.gz', 'gzip.open'),
    ('test.zip', 'zipfile.ZipFile'),
])
def test_decompress_file_gz(log_key: str, decompression_function: str,
                            aws_bucket: aws_s3.AWSBucket):
    """
    Test that the decompress_file method uses the proper function depending
    on the compression algorithm.

    Parameters
    ----------
    log_key : str
        File that should be decompressed.
    decompression_function : str
        Function that should be used to decompress the file.
    aws_bucket : aws_s3.AWSBucket
        Instance of the AWSBucket class.
    """
    with patch(decompression_function) as mock_decompression, \
         patch('io.BytesIO') as mock_io:
        aws_bucket.decompress_file(log_key)
        mock_decompression.assert_called_once()
        mock_io.assert_called_once()


@pytest.mark.parametrize('log_key', ['test.snappy'])
def test_decompress_file_snappy_skip(log_key: str, aws_bucket: aws_s3.AWSBucket):
    """
    Test that the decompress_file function doesn't raise an exception when
    used with snappy files and skip_on_error is set to False.

    Parameters
    ----------
    log_key : str
        File that should be decompressed.
    aws_bucket : aws_s3.AWSBucket
        Instance of the AWSBucket class.
    """
    aws_bucket.skip_on_error = True
    with patch('io.BytesIO'):
        aws_bucket.decompress_file(log_key)


@pytest.mark.parametrize('log_key, skip_on_error, expected_exception', [
    ('test.snappy', False, SystemExit),
])
def test_decompress_snappy_ko(log_key: str, skip_on_error: bool, expected_exception: Exception,
                              aws_bucket: aws_s3.AWSBucket):
    """
    Test that the decompress_file method raises an exception when used with
    a snappy compressed file.

    Parameters
    ----------
    log_key : str
        File that should be decompressed.
    skip_on_error : bool
        If the skip_on_error is disabled or not.
    expected_exception : Exception
        Exception that should be raised.
    aws_bucket : aws_s3.AWSBucket
        Instance of the AWSBucket class.
    """
    aws_bucket.skip_on_error = skip_on_error
    with patch('io.BytesIO'), pytest.raises(expected_exception) as e:
        aws_bucket.decompress_file(log_key)
    assert e.value.code == 8


def test_decompress_file_ko(bad_compressed_file, aws_bucket: aws_s3.AWSBucket):
    """
    Test that the decompress_file method exits with exit code 8 when
    decompressing a corrupted file.

    Parameters
    ----------
    bad_compressed_file : NamedTemporaryFile
        Corrupted zip or gzip file.
    """
    with patch(
            'io.BytesIO', return_value=io.TextIOWrapper(bad_compressed_file)),\
         pytest.raises(SystemExit) as e:
        aws_bucket.decompress_file(bad_compressed_file.name)
    assert e.value.code == 8


@pytest.mark.parametrize('log_file, skip_on_error', [
    (f'{logs_path}/WAF/aws-waf', False),
    (f'{logs_path}/WAF/aws-waf', True),
    (f'{logs_path}/WAF/aws-waf-invalid-json', True),
    (f'{logs_path}/WAF/aws-waf-wrong-structure', True),
])
def test_aws_waf_load_information_from_file(log_file: str, aws_waf_bucket: aws_s3.AWSWAFBucket,
                                            skip_on_error: bool):
    """
    Test AWSWAFBucket's implementation of the load_information_from_file method.

    Parameters
    ----------
    log_file : str
        File that should be decompressed.
    aws_waf_bucket : aws_s3.AWSWAFBucket
        Instance of the AWSWAFBucket class.
    skip_on_error : bool
        If the skip_on_error is disabled or not.
    """
    aws_waf_bucket.skip_on_error = skip_on_error
    with open(log_file, 'rb') as f:
        aws_waf_bucket.client.get_object.return_value.__getitem__.return_value = f
        aws_waf_bucket.load_information_from_file(log_file)


@pytest.mark.parametrize('log_file, skip_on_error, expected_exception', [
    (f'{logs_path}/WAF/aws-waf-invalid-json', False, SystemExit),
    (f'{logs_path}/WAF/aws-waf-wrong-structure', False, SystemExit),
])
def test_aws_waf_load_information_from_file_ko(
        log_file: str, skip_on_error: bool,
        expected_exception: Exception,
        aws_waf_bucket: aws_s3.AWSWAFBucket):
    """
    Test that AWSWAFBucket's implementation of the load_information_from_file method raises
    an exception when called with invalid arguments.

    Parameters
    ----------
    log_file : str
        File that should be decompressed.
    skip_on_error : bool
        If the skip_on_error is disabled or not.
    expected_exception : Exception
        Exception that should be raised.
    aws_waf_bucket : aws_s3.AWSWAFBucket
        Instance of the AWSWAFBucket class.
    """
    aws_waf_bucket.skip_on_error = skip_on_error
    with open(log_file, 'rb') as f, \
         pytest.raises(expected_exception):
        aws_waf_bucket.client.get_object.return_value.__getitem__.return_value = f
        aws_waf_bucket.load_information_from_file(log_file)


@pytest.mark.parametrize('date, expected_date', [
    ('2021/1/19', '20210119'),
    ('2021/1/1', '20210101'),
    ('2021/01/01', '20210101'),
    ('2000/2/12', '20000212'),
    ('2022/02/1', '20220201')
])
def test_config_format_created_date(date: str, expected_date: str, aws_config_bucket):
    """
    Test AWSConfigBucket's format_created_date method.

    Parameters
    ----------
    date : str
        The date introduced.
    expected_date : str
        The date that the method should return.
    aws_config_bucket : aws_s3.AWSConfigBucket
        Instance of the AWSConfigBucket class.
    """
    assert aws_config_bucket._format_created_date(date) == expected_date


@pytest.mark.parametrize('log_file, expected_date', [
    ({'Key' : 'AWSLogs/166157441623/elasticloadbalancing/us-west-1/2021/12/21/166157441623_elasticloadbalancing'}, 20211221),
    ({'Key' : 'AWSLogs/875611522134/elasticloadbalancing/us-west-1/2020/01/03/166157441623_elasticloadbalancing'}, 20200103),
    ({'Key' : '981837383623/iplogs/2020-09-20/2020-09-20-00-00-moyl.csv.gz'}, 20200920),
    ({'Key' : '836629801214/iplogs/2021-01-18/2021-01-18-00-00-zxsb.csv.gz'}, 20210118),
    ({'Key' : '2020/09/30/13/firehose_guardduty-1-2020-09-30-13-17-05-532e184c-1hfba.zip'}, 20200930),
    ({'Key' : '2020/10/15/03/firehose_guardduty-1-2020-10-15-03-22-01-ea728dd1-763a4.zip'}, 20201015),
    ({'Key' : 'AWSLogs/567970947422/GuardDuty/us-east-1/2022/10/21/ec7b0b8c-5ec8-32ec-8e77-c738515b4f6f.jsonl.gz'}, 20221021),
    ({'Key' : '2021/03/18/aws-waf-logs-delivery-stream-1-2021-03-18-10-32-48-77baca34f-efad-4f14-45bd7871'}, 20210318),
    ({'Key' : '2021/09/06/aws-waf-logs-delivery-stream-1-2021-09-06-21-02-18-8ba031bbd-babf-4c6a-83ba282c'}, 20210906),
    ({'Key' : '2021-11-12-09-11-26-B9F9F891E8D0EB13'}, 20211112),
    ({'Key' : '20-03-02-21-02-43-A8269E82CA8BDD21', 'LastModified' : datetime.strptime('2021/01/23', '%Y/%m/%d')}, 20210123)
])
def test_custom_get_creation_date(log_file: dict, expected_date: int, aws_custom_bucket : aws_s3.AWSCustomBucket):
    """
    Test AWSCustomBucket's get_creation_date method.
    Parameters
    ----------
    log_file : dict
        The log file introduced
    expected_date : int
        The date that the method should return.
    aws_custom_bucket : aws_s3.AWSCustomBucket
        Instance of the AWSCustomBucket class.
    """
    assert aws_custom_bucket.get_creation_date(log_file) == expected_date
