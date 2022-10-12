# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from copy import deepcopy

sys.modules['boto3'] = MagicMock()
sys.modules['botocore'] = MagicMock()

import aws_s3


AWS_BASE_PARAMS = [
    [
        {"access_key": "AAAAAAAAAAAAAAAAAAAA"},
        {"secret_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        {"iam_role_arn": ""},
    ],
]


AWS_BUCKET_PARAMS = [
    AWS_BASE_PARAMS[0] + [
        {"access_key": "AAAAAAAAAAAAAAAAAAAA"},
        {"secret_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        {"iam_role_arn": ""},
        {"reparse": False},
        {"profile": ""},
        {"bucket": "test_bucket"},
        {"only_logs_after": ""},
        {"skip_on_error": False},
        {"account_alias": ""},
        {"prefix": ""},
        {"suffix": ""},
        {"delete_file": False},
        {"aws_organization_id": ""},
        {"region": ""},
        {"discard_field": ""},
        {"discard_regex": ""},
        {"sts_endpoint": ""},
        {"service_endpoint": ""}
    ],
]


@pytest.fixture(params=deepcopy(AWS_BUCKET_PARAMS))
def aws_bucket(request):
    """
    Return a AWSBucket instance.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    with patch('aws_s3.AWSBucket.get_client'), \
         patch('sqlite3.connect'), \
         patch('utils.get_wazuh_version'):
        return aws_s3.AWSBucket(**{k: v for i in request.param for k, v in i.items()})


@pytest.fixture(params=deepcopy(AWS_BUCKET_PARAMS))
def aws_waf_bucket(request):
    """
    Return a AWSWAFBucket instance.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    with patch('aws_s3.AWSWAFBucket.get_client'), \
         patch('aws_s3.AWSWAFBucket.get_sts_client'), \
         patch('sqlite3.connect'), \
         patch('utils.get_wazuh_version'):
        return aws_s3.AWSWAFBucket(**{k: v for i in request.param for k, v in i.items()})


@pytest.fixture(params=deepcopy(AWS_BUCKET_PARAMS))
def aws_config_bucket(request):
    """
    Return a AWSConfigBucket instance.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    with patch('aws_s3.AWSConfigBucket.get_client'), \
         patch('aws_s3.AWSConfigBucket.get_sts_client'), \
         patch('sqlite3.connect'), \
         patch('utils.get_wazuh_version'):
        return aws_s3.AWSConfigBucket(**{k: v for i in request.param for k, v in i.items()})


@pytest.fixture(params=deepcopy(AWS_BUCKET_PARAMS))
def aws_custom_bucket(request):
    """
    Return a AWSCustomBucket instance.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    with patch('aws_s3.AWSCustomBucket.get_client'), \
         patch('aws_s3.AWSCustomBucket.get_sts_client'), \
         patch('sqlite3.connect'), \
         patch('utils.get_wazuh_version'):
        return aws_s3.AWSCustomBucket(**{k: v for i in request.param for k, v in i.items()})   


@pytest.fixture(params=['.gz', '.zip'])
def bad_compressed_file(request):
    """
    Return an invalid zip or gzip file.

    Parameters
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    tmp_file = tempfile.NamedTemporaryFile(suffix=request.param)
    tmp_file.write(os.urandom(512))

    yield tmp_file

    tmp_file.close()
