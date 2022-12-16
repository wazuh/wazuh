import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'services'))
import aws_service

TEST_TABLE_NAME = "cloudtrail"
TEST_SERVICE_NAME = "s3"
TEST_ACCESS_KEY = "test_access_key"
TEST_SECRET_KEY = "test_secret_key"
TEST_AWS_PROFILE = "test_aws_profile"
TEST_IAM_ROLE_ARN = "test_iam_role_arn"
TEST_IAM_ROLE_DURATION = '1d'
TEST_ACCOUNT_ID = "123456789123"
TEST_ACCOUNT_ALIAS = "test_account_alias"
TEST_ORGANIZATION_ID = "test_organization_id"
TEST_TOKEN = 'test_token'
TEST_CREATION_DATE = "2022-01-01"
TEST_BUCKET = "test_bucket"
TEST_SERVICE = "test_service"
TEST_PREFIX = "test_prefix"
TEST_SUFFIX = "test_suffix"
TEST_REGION = "us-east-1"
TEST_DISCARD_FIELD = "test_field"
TEST_DISCARD_REGEX = "test_regex"
TEST_ONLY_LOGS_AFTER = "20220101"
TEST_ONLY_LOGS_AFTER_WITH_FORMAT = "2022-01-01 00:00:00.0"

TEST_SERVICE_ENDPOINT = 'test_service_endpoint'
TEST_STS_ENDPOINT = "test_sts_endpoint"

TEST_LOG_FULL_PATH_1 = 'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0030Z_aaaa.json.gz'
TEST_LOG_FULL_PATH_2 = 'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T00015Z_aaaa.json.gz'

WAZUH_VERSION = "4.5.0"

TEST_WAZUH_PATH = "/var/ossec"
TEST_DATABASE = "test"
TEST_MESSAGE = "test_message"
QUEUE_PATH = 'queue/sockets/queue'
WODLE_PATH = 'wodles/aws'

data_path = os.path.join(os.path.dirname(__file__), 'data')

# Error codes
INVALID_CREDENTIALS_ERROR_CODE = 3
METADATA_ERROR_CODE = 5
UNABLE_TO_CREATE_DB = 6
DECOMPRESS_FILE_ERROR_CODE = 8
UNABLE_TO_CONNECT_SOCKET_ERROR_CODE = 11
INVALID_TYPE_ERROR_CODE = 12
SENDING_MESSAGE_SOCKET_ERROR_CODE = 13
INVALID_PREFIX_ERROR_CODE = 18


def get_WazuhIntegration_parameters(db_name: str = TEST_DATABASE, db_table_name: str = TEST_TABLE_NAME,
                                    service_name: str = TEST_SERVICE_NAME, aws_profile: str = TEST_AWS_PROFILE,
                                    access_key: str = None, secret_key: str = None, iam_role_arn: str = None,
                                    region: str = None, discard_field: str = None, discard_regex: str = None,
                                    sts_endpoint: str = None, service_endpoint: str = None,
                                    iam_role_duration: str = None):
    """Return a dict containing every parameter supported by WazuhIntegration. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    db_name : str
        The name of the database file to be created
    db_table_name : str
        The name of the table to be created for the given bucket or service
    service_name : str
        Name of the service.
    access_key : str
        Access key value.
    secret_key : str
        Secret key value.
    aws_profile : str
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

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'db_name': db_name, 'db_table_name': db_table_name, 'service_name': service_name, 'access_key': access_key,
            'secret_key': secret_key, 'aws_profile': aws_profile, 'iam_role_arn': iam_role_arn, 'region': region,
            'discard_field': discard_field, 'discard_regex': discard_regex, 'sts_endpoint': sts_endpoint,
            'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}


def get_AWSBucket_parameters(db_table_name: str = TEST_TABLE_NAME, bucket: str = TEST_BUCKET, reparse: bool = False,
                             aws_profile: str = TEST_AWS_PROFILE, access_key: str = None, secret_key: str = None,
                             iam_role_arn: str = None, only_logs_after: str = None, skip_on_error: bool = False,
                             account_alias: str = None, prefix: str = "", suffix: str = "", delete_file: bool = False,
                             aws_organization_id: str = None, region: str = None, discard_field: str = None,
                             discard_regex: str = None, sts_endpoint: str = None, service_endpoint: str = None,
                             iam_role_duration: str = None):
    """Return a dict containing every parameter supported by AWSBucket. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    TODO

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'db_table_name': db_table_name, 'bucket': bucket, 'reparse': reparse, 'aws_profile': aws_profile,
            'access_key': access_key, 'secret_key': secret_key, 'iam_role_arn': iam_role_arn,
            'only_logs_after': only_logs_after, 'skip_on_error': skip_on_error, 'account_alias': account_alias,
            'prefix': prefix, 'suffix': suffix, 'delete_file': delete_file, 'aws_organization_id': aws_organization_id,
            'region': region, 'discard_field': discard_field, 'discard_regex': discard_regex,
            'sts_endpoint': sts_endpoint, 'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}

def get_AWSService_parameters(db_table_name: str = TEST_TABLE_NAME, service_name: str = 'cloudwatchlogs',
                              reparse: bool = False, access_key: str = None, secret_key: str = None,
                              aws_profile: str = TEST_AWS_PROFILE, iam_role_arn: str = None,
                              only_logs_after: str = None, region: str = None, discard_field: str = None,
                              discard_regex: str = None, sts_endpoint: str = None, service_endpoint: str = None,
                              iam_role_duration: str = None):

    """Return a dict containing every parameter supported by AWSService. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    TODO

    Returns
    -------
    dict
        A dict containing the configuration parameters with their default values.
    """
    return {'db_table_name': db_table_name, 'service_name': service_name, 'reparse': reparse, 'access_key': access_key,
            'secret_key': secret_key, 'aws_profile': aws_profile, 'iam_role_arn': iam_role_arn,
            'only_logs_after': only_logs_after, 'region': region, 'discard_field': discard_field,
            'discard_regex': discard_regex, 'sts_endpoint': sts_endpoint,
            'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration}

def get_mocked_WazuhIntegration(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return wazuh_integration.WazuhIntegration(**get_WazuhIntegration_parameters(**kwargs))

def get_mocked_AWSBucket(**kwargs):
    with patch('wazuh_integration.WazuhIntegration.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return aws_bucket.AWSBucket(**get_AWSBucket_parameters(**kwargs))

def get_mocked_bucket(class_=aws_bucket.AWSBucket, **kwargs):
    with patch('wazuh_integration.WazuhIntegration.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return class_(**get_AWSBucket_parameters(**kwargs))

def get_mocked_service(class_=aws_service.AWSService, **kwargs):
    with patch('wazuh_integration.WazuhIntegration.check_metadata_version'), \
            patch('wazuh_integration.WazuhIntegration.get_client'), \
            patch('wazuh_integration.sqlite3.connect'), \
            patch('wazuh_integration.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return class_(**get_AWSService_parameters(**kwargs))

def database_execute_script(connector, sql_file):
    with open(os.path.join(data_path, sql_file)) as f:
        connector.cursor().executescript(f.read())
    connector.commit()

def database_execute_query(connector, query, query_params = {}):
    row = connector.execute(query, query_params).fetchone()
    return row[0] if row and len(row) == 1 else row
