# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import copy
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'services'))
import aws_service

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'subscribers'))
import sqs_queue
import s3_log_handler

TEST_TABLE_NAME = "cloudtrail"
TEST_SERVICE_NAME = "s3"
TEST_AWS_PROFILE = "test_aws_profile"
TEST_IAM_ROLE_ARN = "arn:aws:iam::123455678912:role/Role"
TEST_IAM_ROLE_DURATION = '3600'
TEST_ACCOUNT_ID = "123456789123"
TEST_ACCOUNT_ALIAS = "test_account_alias"
TEST_ORGANIZATION_ID = "test_organization_id"
TEST_TOKEN = 'test_token'
TEST_CREATION_DATE = "2022-01-01"
TEST_BUCKET = "test-bucket"
TEST_SERVICE = "test-service"
TEST_SQS_NAME = "test-sqs"
TEST_PREFIX = "test_prefix"
TEST_SUFFIX = "test_suffix"
TEST_REGION = "us-east-1"
TEST_DISCARD_FIELD = "test_field"
TEST_DISCARD_REGEX = "test_regex"
TEST_ONLY_LOGS_AFTER = "20220101"
TEST_ONLY_LOGS_AFTER_WITH_FORMAT = "2022-01-01 00:00:00.0"
TEST_LOG_KEY = "123456789_CloudTrail-us-east-1_20190401T00015Z_aaaa.json.gz"
TEST_FULL_PREFIX = "base/account_id/service/region/"
TEST_EXTERNAL_ID = "external-id-Sec-Lake"

TEST_SERVICE_ENDPOINT = 'test_service_endpoint'
TEST_STS_ENDPOINT = "test_sts_endpoint"

TEST_LOG_FULL_PATH_CLOUDTRAIL_1 = 'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_' \
                                  '20190401T0030Z_aaaa.json.gz'
TEST_LOG_FULL_PATH_CLOUDTRAIL_2 = 'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_' \
                                  '20190401T00015Z_aaaa.json.gz'
TEST_LOG_FULL_PATH_CUSTOM_1 = 'custom/2019/04/15/07/firehose_custom-1-2019-04-15-09-16-03.zip'
TEST_LOG_FULL_PATH_CUSTOM_2 = 'custom/2019/04/15/07/firehose_custom-1-2019-04-15-13-19-03.zip'
TEST_LOG_FULL_PATH_CONFIG_1 = 'AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_' \
                              'ConfigHistory_20190415T020500Z.json.gz'

LIST_OBJECT_V2 = {'CommonPrefixes': [{'Prefix': f'AWSLogs/{TEST_REGION}/'},
                                     {'Prefix': f'AWSLogs/prefix/{TEST_REGION}/'}]}

LIST_OBJECT_V2_NO_PREFIXES = {'Contents': [{
    'Key': '',
    'OtherKey': 'value'}],
    'IsTruncated': False
}

LIST_OBJECT_V2_TRUNCATED = copy.deepcopy(LIST_OBJECT_V2_NO_PREFIXES)
LIST_OBJECT_V2_TRUNCATED.update({'IsTruncated': True, 'NextContinuationToken': 'Token'})

WAZUH_VERSION = "4.5.0"

TEST_WAZUH_PATH = "/var/ossec"
TEST_DATABASE = "test"
TEST_MESSAGE = "test_message"
QUEUE_PATH = 'queue/sockets/queue'
WODLE_PATH = 'wodles/aws'

SQL_COUNT_ROWS = """SELECT count(*) FROM {table_name};"""

data_path = os.path.join(os.path.dirname(__file__), 'data')

# Error codes
UNKNOWN_ERROR_CODE = 1
INVALID_CREDENTIALS_ERROR_CODE = 3
METADATA_ERROR_CODE = 5
UNABLE_TO_CREATE_DB = 6
UNEXPECTED_ERROR_WORKING_WITH_S3 = 7
DECOMPRESS_FILE_ERROR_CODE = 8
PARSE_FILE_ERROR_CODE = 9
UNABLE_TO_CONNECT_SOCKET_ERROR_CODE = 11
INVALID_TYPE_ERROR_CODE = 12
SENDING_MESSAGE_SOCKET_ERROR_CODE = 13
EMPTY_BUCKET_ERROR_CODE = 14
INVALID_ENDPOINT_ERROR_CODE = 15
THROTTLING_ERROR_CODE = 16
INVALID_KEY_FORMAT_ERROR_CODE = 17
INVALID_PREFIX_ERROR_CODE = 18
INVALID_REQUEST_TIME_ERROR_CODE = 19
UNABLE_TO_FETCH_DELETE_FROM_QUEUE = 21
INVALID_REGION_ERROR_CODE = 22


def get_wazuh_integration_parameters(service_name: str = TEST_SERVICE_NAME, profile: str = TEST_AWS_PROFILE,
                                     iam_role_arn: str = None, region: str = None, discard_field: str = None,
                                     discard_regex: str = None, sts_endpoint: str = None, service_endpoint: str = None,
                                     iam_role_duration: str = None, external_id: str = None,
                                     skip_on_error: bool = False):
    """Return a dict containing every parameter supported by WazuhIntegration. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    service_name : str
        Name of the service.
    profile : str
        AWS profile name.
    iam_role_arn : str
        IAM Role ARN value.
    region : str
        Region name.
    discard_field : list of str
        List of field names to be discarded.
    discard_regex : str
        Regex to be applied to the fields to determine if they should be discarded.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.
    external_id: str
        AWS external ID for IAM Role assumption when using Security Lake.
    skip_on_error : bool
        Whether to continue processing logs or stop when an error takes place.

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'service_name': service_name, 'profile': profile, 'iam_role_arn': iam_role_arn,
            'region': region, 'discard_field': discard_field, 'discard_regex': discard_regex,
            'sts_endpoint': sts_endpoint, 'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration,
            'external_id': external_id, 'skip_on_error': skip_on_error}


def get_wazuh_aws_database_parameters(service_name: str = TEST_SERVICE_NAME, profile: str = TEST_AWS_PROFILE,
                                      db_name: str = TEST_DATABASE,
                                      iam_role_arn: str = None, region: str = None, discard_field: str = None,
                                      discard_regex: str = None, sts_endpoint: str = None, service_endpoint: str = None,
                                      iam_role_duration: str = None, external_id: str = None):
    """Return a dict containing every parameter supported by WazuhAWSDatabase.

    Parameters
    ----------
    service_name : str
        Name of the service.
    profile : str
        AWS profile name.
    db_name : str
        Database name.
    iam_role_arn : str
        IAM Role ARN value.
    region : str
        Region name.
    discard_field : list of str
        List of field names to be discarded.
    discard_regex : str
        Regex to be applied to the fields to determine if they should be discarded.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.
    external_id: str
        AWS external ID for IAM Role assumption when using Security Lake.

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'service_name': service_name, 'profile': profile, 'db_name': db_name, 'iam_role_arn': iam_role_arn,
            'region': region, 'discard_field': discard_field, 'discard_regex': discard_regex,
            'sts_endpoint': sts_endpoint, 'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration,
            'external_id': external_id}


def get_aws_bucket_parameters(db_table_name: str = TEST_TABLE_NAME, bucket: str = TEST_BUCKET, reparse: bool = False,
                              profile: str = TEST_AWS_PROFILE,
                              iam_role_arn: str = None, only_logs_after: str = None, skip_on_error: bool = False,
                              account_alias: str = None, prefix: str = "", suffix: str = "", delete_file: bool = False,
                              aws_organization_id: str = None, region: str = None, discard_field: str = None,
                              discard_regex: str = None, sts_endpoint: str = None, service_endpoint: str = None,
                              iam_role_duration: str = None):
    """Return a dict containing every parameter supported by AWSBucket. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    db_table_name : str
        The name of the table to be created for the given bucket or service.
    bucket : str
        Name of the bucket.
    reparse : bool
        Whether to parse already parsed logs or not.
    profile : str
        AWS profile name.
    iam_role_arn : str
        IAM Role ARN value.
    only_logs_after : str
        Date after which obtain logs.
    skip_on_error : bool
        Whether to continue processing logs or stop when an error takes place.
    account_alias: str
        Alias of the AWS account where the bucket is.
    prefix : str
        Prefix to filter files in bucket.
    suffix : str
        Suffix to filter files in bucket.
    delete_file : bool
        Whether to delete an already processed file from a bucket or not.
    aws_organization_id : str
        The AWS organization ID.
    region : str
        Region name.
    discard_field : list of str
        List of field names to be discarded.
    discard_regex : str
        Regex to be applied to the fields to determine if they should be discarded.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'db_table_name': db_table_name, 'bucket': bucket, 'reparse': reparse, 'profile': profile,
            'iam_role_arn': iam_role_arn,
            'only_logs_after': only_logs_after, 'skip_on_error': skip_on_error, 'account_alias': account_alias,
            'prefix': prefix, 'suffix': suffix, 'delete_file': delete_file, 'aws_organization_id': aws_organization_id,
            'region': region, 'discard_field': discard_field, 'discard_regex': discard_regex,
            'sts_endpoint': sts_endpoint, 'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}


def get_aws_service_parameters(db_table_name: str = TEST_TABLE_NAME, service_name: str = 'cloudwatchlogs',
                               reparse: bool = False,
                               profile: str = TEST_AWS_PROFILE, iam_role_arn: str = None,
                               only_logs_after: str = None, account_alias: str = None, region: str = None, aws_log_groups: str = None,
                               remove_log_streams: bool = None, discard_field: str = None,
                               discard_regex: str = None, sts_endpoint: str = None, service_endpoint: str = None,
                               iam_role_duration: str = None):
    """Return a dict containing every parameter supported by AWSService. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    reparse : bool
        Whether to parse already parsed logs or not.
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    service_name : str
        Service name to extract logs from.
    only_logs_after : str
        Date after which obtain logs.
    account_alias: str
        AWS account alias.
    region : str
        Region name.
    aws_log_groups : str
        String containing a list of log group names separated by a comma.
    remove_log_streams: str
        Indicate if log streams should be removed after being fetched.
    db_table_name : str
        The name of the table to be created for the given bucket or service.
    discard_field : str
        Name of the event field to apply the regex value on.
    discard_regex : str
        REGEX value to determine whether an event should be skipped.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'db_table_name': db_table_name, 'service_name': service_name, 'reparse': reparse, 'access_key': access_key,
            'secret_key': secret_key, 'profile': profile, 'iam_role_arn': iam_role_arn,
            'only_logs_after': only_logs_after, 'account_alias': account_alias, 'region': region, 'aws_log_groups': aws_log_groups,
            'remove_log_streams': remove_log_streams, 'discard_field': discard_field,
            'discard_regex': discard_regex, 'sts_endpoint': sts_endpoint,
            'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}


def get_aws_sqs_queue_parameters(name: str = TEST_SQS_NAME, external_id: str = TEST_EXTERNAL_ID,
                                 iam_role_arn: str = TEST_IAM_ROLE_ARN, iam_role_duration: str = None,
                                 sts_endpoint: str = None, service_endpoint: str = None):
    """Return a dict containing every parameter supported by AWSSQSQueue. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    name: str
        Name of the SQS Queue.
    external_id : str
        The name of the External ID to use.
    iam_role_arn : str
        IAM Role.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'name': name, 'external_id': external_id, 'iam_role_arn': iam_role_arn,
            'sts_endpoint': sts_endpoint, 'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}


def get_aws_s3_log_handler_parameters(iam_role_arn: str = None, iam_role_duration: str = None,
                                      service_endpoint: str = None, sts_endpoint: str = None):
    """Return a dict containing every parameter supported by AWSSLSubscriberBucket.
    Used to simulate different ossec.conf configurations.

    Parameters
    ----------
    iam_role_arn : str
        IAM Role.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'iam_role_arn': iam_role_arn, 'iam_role_duration': iam_role_duration,
            'sts_endpoint': sts_endpoint, 'service_endpoint': service_endpoint}


def get_mocked_wazuh_integration(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return wazuh_integration.WazuhIntegration(**get_wazuh_integration_parameters(**kwargs))


def get_mocked_wazuh_aws_database(**kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return wazuh_integration.WazuhAWSDatabase(**get_wazuh_aws_database_parameters(**kwargs))


def get_mocked_aws_bucket(**kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return aws_bucket.AWSBucket(**get_aws_bucket_parameters(**kwargs))


def get_mocked_bucket(class_=aws_bucket.AWSBucket, **kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return class_(**get_aws_bucket_parameters(**kwargs))


def get_mocked_service(class_=aws_service.AWSService, **kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return class_(**get_aws_service_parameters(**kwargs))


def get_mocked_aws_sqs_queue(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION), \
            patch('s3_log_handler.AWSS3LogHandler.__init__') as mocked_handler, \
            patch('sqs_message_processor.AWSQueueMessageProcessor.__init__') as mocked_processor:
        return sqs_queue.AWSSQSQueue(message_processor=mocked_processor, bucket_handler=mocked_handler,
                                     **get_aws_sqs_queue_parameters(**kwargs))


def get_mocked_aws_sl_subscriber_bucket(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return s3_log_handler.AWSSLSubscriberBucket(**get_aws_s3_log_handler_parameters(**kwargs))


def database_execute_script(connector, sql_file):
    with open(os.path.join(data_path, sql_file)) as f:
        connector.cursor().executescript(f.read())
    connector.commit()


def database_execute_query(connector, query, query_params={}):
    row = connector.execute(query, query_params).fetchone()
    return row[0] if row and len(row) == 1 else row
