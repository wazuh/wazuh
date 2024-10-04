# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy

TEST_HARDCODED_WAZUH_VERSION = "4.5.0"
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
TEST_MESSAGE = "test_message"
TEST_DATABASE = "test"
TEST_WAZUH_PATH = "/var/ossec"
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

# ERROR CODES
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
