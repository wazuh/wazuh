import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3


TEST_ACCESS_KEY = "test_access_key"
TEST_SECRET_KEY = "test_secret_key"
TEST_AWS_PROFILE = "test_aws_profile"
TEST_IAM_ROLE_ARN = "test_iam_role_arn"
TEST_TOKEN = 'test_token'
TEST_SERVICE_ENDPOINT = 'test_endpoint'
TEST_IAM_ROLE_DURATION = '1d'
TEST_WAZUH_PATH = "/var/ossec"
TEST_DATABASE = "test"
TEST_MESSAGE = "test_message"
QUEUE_PATH = 'queue/sockets/queue'
WODLE_PATH = 'wodles/aws'

WAZUH_VERSION = "4.5.0"

data_path = os.path.join(os.path.dirname(__file__), 'data')


def get_WazuhIntegration_parameters(access_key: str = TEST_ACCESS_KEY, secret_key: str = TEST_SECRET_KEY,
                                    aws_profile: str = TEST_AWS_PROFILE, iam_role_arn: str = TEST_IAM_ROLE_ARN,
                                    service_name: str = None, region: str = None, bucket: str = None,
                                    discard_field: str = None, discard_regex: str = None, sts_endpoint: str = None,
                                    service_endpoint: str = None, iam_role_duration: str = None,
                                    db_name: str = TEST_DATABASE):
    """Return a dict containing every parameter supported by WazuhIntegration. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    access_key : str
        Access key value.
    secret_key : str
        Secret key value.
    aws_profile : str
        AWS profile name.
    iam_role_arn : str
        IAM Role ARN value.
    service_name : str
        Name of the service.
    region : str
        Region name.
    bucket : str
        Bucket name to extract logs from.
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
    db_name : str
        The name of the database file to be created

    Returns
    -------
    dict
        A dict containing the configuration parameters with their values.
    """
    return {'access_key': access_key, 'secret_key': secret_key, 'aws_profile': aws_profile,
            'iam_role_arn': iam_role_arn, 'service_name': service_name, 'region': region, 'bucket': bucket,
            'discard_field': discard_field, 'discard_regex': discard_regex, 'sts_endpoint': sts_endpoint,
            'service_endpoint': service_endpoint, 'iam_role_duration': iam_role_duration, 'db_name': db_name}

def get_mocked_WazuhIntegration(**kwargs):
    with patch('aws_s3.WazuhIntegration.check_metadata_version'), \
            patch('aws_s3.WazuhIntegration.get_client'), \
            patch('aws_s3.sqlite3.connect'), \
            patch('aws_s3.utils.find_wazuh_path', return_value=TEST_WAZUH_PATH), \
            patch('aws_s3.utils.get_wazuh_version', return_value=WAZUH_VERSION):
        return aws_s3.WazuhIntegration(**get_WazuhIntegration_parameters(**kwargs))

def database_execute_script(connector, sql_file):
    with open(os.path.join(data_path, sql_file)) as f:
        connector.cursor().executescript(f.read())
    connector.commit()

def database_execute_query(connector, query, query_params = {}):
    query = connector.execute(query, **query_params)
    return query.fetchone()[0]
