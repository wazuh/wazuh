# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
import pytest
from unittest.mock import patch
from copy import deepcopy


import aws_s3
from .data.fixture_parameters import *


@pytest.fixture(params= deepcopy(AWS_INTEGRATION_PARAMS))
def wazuh_integration(request):
    """
    Return a WazuhIntegration instance.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    with patch('aws_s3.WazuhIntegration.get_client'), \
         patch('sqlite3.connect'):
        return aws_s3.WazuhIntegration(**{k: v for i in request.param for k, v in i.items()})


@pytest.fixture(params= deepcopy(AWS_BUCKET_PARAMS))
def aws_bucket(request):
    """
    Return a AWSBucket instance.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.
    """
    with patch('aws_s3.AWSBucket.get_client'), \
         patch('sqlite3.connect'):
        return aws_s3.AWSBucket(**{k: v for i in request.param for k, v in i.items()})

@pytest.fixture(params= deepcopy(AWS_BUCKET_PARAMS))
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
         patch('sqlite3.connect'):
        return aws_s3.AWSWAFBucket(**{k: v for i in request.param for k, v in i.items()})

