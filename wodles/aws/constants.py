from os import path

# RETRIES CONFIGURATIONS
RETRY_ATTEMPTS_KEY: str = "max_attempts"
RETRY_MODE_CONFIG_KEY: str = "retry_mode"
RETRY_MODE_BOTO_KEY: str = "mode"
WAZUH_DEFAULT_RETRY_CONFIGURATION = {RETRY_ATTEMPTS_KEY: 10, RETRY_MODE_BOTO_KEY: 'standard'}

# AWS BUCKET CONFIGURATIONS
MAX_AWS_BUCKET_RECORD_RETENTION = 500
AWS_BUCKET_DB_DATE_FORMAT = "%Y%m%d"

# CLOUDTRAIL CONFIGURATIONS
AWS_CLOUDTRAIL_DYNAMIC_FIELDS = ['additionalEventData', 'responseElements', 'requestParameters']

# INSPECTOR CONFIGURATIONS
INSPECTOR_SUPPORTED_REGIONS = (
    'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-2', 'eu-central-1', 'eu-north-1', 'eu-west-1',
    'eu-west-2', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
)

# DATABASE VALUES
DEFAULT_AWS_SERVICE_DATABASE_NAME = "aws_services"
DEFAULT_AWS_SERVICE_TABLENAME = "aws_services"
DEFAULT_AWS_BUCKET_DATABASE_NAME = "s3_cloudtrail"

# REGIONS
ALL_REGIONS = (
    'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ca-central-1', 'eu-central-1',
    'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'il-central-1',
    'me-central-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
)
DEFAULT_AWS_INTEGRATION_GOV_REGIONS = {'us-gov-east-1', 'us-gov-west-1'}
SERVICES_REQUIRING_REGION = {'inspector', 'cloudwatchlogs'}


# URLS
RETRY_CONFIGURATION_URL = 'https://documentation.wazuh.com/current/amazon/services/prerequisites/' \
                          'considerations.html#Connection-configuration-for-retries'
GUARDDUTY_URL = 'https://documentation.wazuh.com/current/amazon/services/supported-services/guardduty.html'
SECURITY_LAKE_IAM_ROLE_AUTHENTICATION_URL = 'https://documentation.wazuh.com/current/cloud-security/amazon/services/' \
                                        'supported-services/security-lake.html#configuring-an-iam-role'

# PATHS
DEFAULT_AWS_CONFIG_PATH = path.join(path.expanduser('~'), '.aws', 'config')

# MSG HEADERS
WAZUH_AWS_MESSAGE_HEADER = "1:Wazuh-AWS:"

# MSG TEMPLATES
AWS_BUCKET_MSG_TEMPLATE = {'integration': 'aws',
                           'aws': {'log_info': {'aws_account_alias': '', 'log_file': '', 's3bucket': ''}}}
AWS_SERVICE_MSG_TEMPLATE = {'integration': 'aws', 'aws': ''}

# AWS INTEGRATION DEPRECATED VALUES
DEPRECATED_AWS_INTEGRATION_TABLES = {'log_progress', 'trail_progress'}

# DEPRECATED MESSAGES
GUARDDUTY_DEPRECATED_MESSAGE = 'The functionality to process GuardDuty logs stored in S3 via Kinesis was deprecated ' \
                               'in {release}. Consider configuring GuardDuty to store its findings directly in an S3 ' \
                               'bucket instead. Check {url} for more information.'

# ERROR CODES
INVALID_CREDENTIALS_ERROR_CODE = "SignatureDoesNotMatch"
INVALID_REQUEST_TIME_ERROR_CODE = "RequestTimeTooSkewed"
THROTTLING_EXCEPTION_ERROR_CODE = "ThrottlingException"

# ERROR MESSAGES
UNKNOWN_ERROR_MESSAGE = "Unexpected error: '{error}'."
INVALID_CREDENTIALS_ERROR_MESSAGE = "Invalid credentials to access S3 Bucket"
INVALID_REQUEST_TIME_ERROR_MESSAGE = "The server datetime and datetime of the AWS environment differ"
THROTTLING_EXCEPTION_ERROR_MESSAGE = "The '{name}' request was denied due to request throttling. " \
                                     "If the problem persists check the following link to learn how to use " \
                                     f"the Retry configuration to avoid it: '{RETRY_CONFIGURATION_URL}'"




