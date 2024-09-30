import os
import sys
from unittest.mock import patch

import aws_constants as test_constants

data_path = os.path.join(os.path.dirname(__file__), 'data')

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'services'))
import aws_service

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'subscribers'))
import sqs_queue
import s3_log_handler


def get_wazuh_integration_parameters(service_name: str = test_constants.TEST_SERVICE_NAME,
                                     profile: str = test_constants.TEST_AWS_PROFILE,
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


def get_wazuh_aws_database_parameters(service_name: str = test_constants.TEST_SERVICE_NAME,
                                      profile: str = test_constants.TEST_AWS_PROFILE,
                                      db_name: str = test_constants.TEST_DATABASE,
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


def get_aws_bucket_parameters(db_table_name: str = test_constants.TEST_TABLE_NAME,
                              bucket: str = test_constants.TEST_BUCKET, reparse: bool = False,
                              profile: str = test_constants.TEST_AWS_PROFILE,
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


def get_aws_service_parameters(db_table_name: str = test_constants.TEST_TABLE_NAME, service_name: str = 'cloudwatchlogs',
                               reparse: bool = False,
                               profile: str = test_constants.TEST_AWS_PROFILE, iam_role_arn: str = None,
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
    return {'db_table_name': db_table_name, 'service_name': service_name, 'reparse': reparse,
            'profile': profile, 'iam_role_arn': iam_role_arn,
            'only_logs_after': only_logs_after, 'account_alias': account_alias, 'region': region,
            'aws_log_groups': aws_log_groups,
            'remove_log_streams': remove_log_streams, 'discard_field': discard_field,
            'discard_regex': discard_regex, 'sts_endpoint': sts_endpoint,
            'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}


def get_aws_sqs_queue_parameters(name: str = test_constants.TEST_SQS_NAME,
                                 external_id: str = test_constants.TEST_EXTERNAL_ID,
                                 iam_role_arn: str = test_constants.TEST_IAM_ROLE_ARN, iam_role_duration: str = None,
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
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION):
        return wazuh_integration.WazuhIntegration(**get_wazuh_integration_parameters(**kwargs))


def get_mocked_wazuh_aws_database(**kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION):
        return wazuh_integration.WazuhAWSDatabase(**get_wazuh_aws_database_parameters(**kwargs))


def get_mocked_aws_bucket(**kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION):
        return aws_bucket.AWSBucket(**get_aws_bucket_parameters(**kwargs))


def get_mocked_bucket(class_=aws_bucket.AWSBucket, **kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION):
        return class_(**get_aws_bucket_parameters(**kwargs))


def get_mocked_service(class_=aws_service.AWSService, **kwargs):
    with patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION):
        return class_(**get_aws_service_parameters(**kwargs))


def get_mocked_aws_sqs_queue(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION), \
            patch('s3_log_handler.AWSS3LogHandler.__init__') as mocked_handler, \
            patch('sqs_message_processor.AWSQueueMessageProcessor.__init__') as mocked_processor:
        return sqs_queue.AWSSQSQueue(message_processor=mocked_processor, bucket_handler=mocked_handler,
                                     **get_aws_sqs_queue_parameters(**kwargs))


def get_mocked_aws_sl_subscriber_bucket(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=test_constants.TEST_HARDCODED_WAZUH_VERSION):
        return s3_log_handler.AWSSLSubscriberBucket(**get_aws_s3_log_handler_parameters(**kwargs))


def database_execute_script(connector, sql_file):
    with open(os.path.join(data_path, sql_file)) as f:
        connector.cursor().executescript(f.read())
    connector.commit()


def database_execute_query(connector, query, query_params={}):
    row = connector.execute(query, query_params).fetchone()
    return row[0] if row and len(row) == 1 else row
