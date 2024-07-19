# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import os
import sys
from unittest.mock import patch


sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils
import constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import cloudtrail


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_aws_cloudtrail_bucket_initializes_properly(mock_logs_bucket):
    """Test if the instances of AWSCloudTrailBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=cloudtrail.AWSCloudTrailBucket)
    mock_logs_bucket.assert_called_once()
    assert instance.service == "CloudTrail"
    assert instance.field_to_load == "Records"


@patch('aws_bucket.AWSBucket.reformat_msg')
def test_aws_cloudtrail_bucket_reformat_msg(mock_reformat):
    """Test 'reformat_msg' method applies the expected format to a given event."""
    event = copy.deepcopy(constants.AWS_BUCKET_MSG_TEMPLATE)
    # Add problematic fields
    for field in constants.AWS_CLOUDTRAIL_DYNAMIC_FIELDS:
        if field == 'requestParameters':
            event['aws'].update({field: {'disableApiTermination': False}})
        else:
            event['aws'].update({field: 'value'})

    instance = utils.get_mocked_bucket(class_=cloudtrail.AWSCloudTrailBucket)
    formatted_event = instance.reformat_msg(event)
    mock_reformat.assert_called_with(instance, event)

    for field in constants.AWS_CLOUDTRAIL_DYNAMIC_FIELDS:
        if field == 'requestParameters':
            # Check disableApiTermination field was cast from bool to dict
            assert isinstance(formatted_event['aws']['requestParameters']['disableApiTermination'], dict)
            assert formatted_event['aws']['requestParameters']['disableApiTermination']['value'] == False
        else:
            # Check dynamic fields were cast from string to dict
            assert isinstance(event['aws'][field], dict)
            assert formatted_event['aws'][field]['string'] == 'value'
