# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
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
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    # Add problematic fields
    for field in cloudtrail.DYNAMIC_FIELDS:
        if field == 'requestParameters':
            event['aws'].update({field: {'disableApiTermination': False}})
        else:
            event['aws'].update({field: 'value'})

    instance = utils.get_mocked_bucket(class_=cloudtrail.AWSCloudTrailBucket)
    formatted_event = instance.reformat_msg(event)
    mock_reformat.assert_called_with(instance, event)

    for field in cloudtrail.DYNAMIC_FIELDS:
        if field == 'requestParameters':
            # Check disableApiTermination field was cast from bool to dict
            assert isinstance(formatted_event['aws']['requestParameters']['disableApiTermination'], dict)
            assert formatted_event['aws']['requestParameters']['disableApiTermination']['value'] == False
        else:
            # Check dynamic fields were cast from string to dict
            assert isinstance(event['aws'][field], dict)
            assert formatted_event['aws'][field]['string'] == 'value'


@patch('aws_bucket.AWSBucket.reformat_msg')
def test_aws_cloudtrail_bucket_reformat_msg_disable_api_termination_already_dict(mock_reformat):
    """reformat_msg leaves disableApiTermination unchanged when it is already a dict (elif branch)."""
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    existing_dict = {'value': True}
    event['aws']['requestParameters'] = {'disableApiTermination': existing_dict.copy()}

    instance = utils.get_mocked_bucket(class_=cloudtrail.AWSCloudTrailBucket)
    formatted_event = instance.reformat_msg(event)

    # dict branch → pass: value must remain unchanged
    assert formatted_event['aws']['requestParameters']['disableApiTermination'] == existing_dict


@patch('builtins.print')
@patch('aws_bucket.AWSBucket.reformat_msg')
def test_aws_cloudtrail_bucket_reformat_msg_disable_api_termination_unexpected_type_prints_warning(
        mock_reformat, mock_print):
    """reformat_msg prints a WARNING when disableApiTermination is neither bool nor dict (else branch)."""
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    event['aws']['requestParameters'] = {'disableApiTermination': 'unexpected_string'}

    instance = utils.get_mocked_bucket(class_=cloudtrail.AWSCloudTrailBucket)
    instance.reformat_msg(event)

    mock_print.assert_called_once()
    assert 'WARNING' in mock_print.call_args.args[0]
