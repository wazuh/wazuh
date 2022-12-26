import pytest
import os
import sys
import copy
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import guardduty

SAMPLE_EVENT_1 = {'key1': 'value1', 'key2': 'value2'}


@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSGuardDutyBucket__init__(mock_custom_bucket):
    """Test if the instances of AWSGuardDutyBucket are created properly."""
    utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)
    mock_custom_bucket.assert_called_once()


@patch('guardduty.AWSGuardDutyBucket.send_msg')
@patch('guardduty.AWSGuardDutyBucket.reformat_msg', return_value=['message'])
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSGuardDutyBucket_send_event(mock_custom_bucket, mock_reformat, mock_send):
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)
    instance.send_event(event)
    mock_reformat.assert_called_with(event)
    mock_send.assert_called()


@pytest.mark.parametrize('reformat_type', ['basic, inherited'])
@patch('aws_bucket.AWSBucket.reformat_msg')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSGuardDutyBucket_reformat_msg(mock_custom_bucket, mock_reformat, reformat_type):
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    event['aws'].update(
        {
            'source': 'guardduty',
            'service':
                {'action':
                    {
                        'portProbeAction':
                            {
                                'portProbeDetails': [
                                    {
                                        "localIpDetails": {
                                            "ipAddressV4": "string"
                                        },
                                        "localPortDetails": {
                                            "port": "number",
                                            "portName": "string"
                                        }
                                    },
                                    {
                                        "localIpDetails": {
                                            "ipAddressV4": "string"
                                        },
                                        "localPortDetails": {
                                            "port": "number",
                                            "portName": "string"
                                        }
                                    }
                                ]
                            }
                    }
                },
            'additional_field': ['element']
        }
    )
    instance = utils.get_mocked_bucket(class_=guardduty.AWSGuardDutyBucket)
    result = []
    
    formatted_event = list(instance.reformat_msg(event))

    if reformat_type == 'basic':
        port_probe_details = event['aws']['service']['action']['portProbeAction']['portProbeDetails']
        for detail in port_probe_details:
            event['aws']['service']['action']['portProbeAction']['portProbeDetails'] = detail
            result.append(event)

        assert result == formatted_event

    else:
        event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
        event['aws'].update(
            {
                'source': 'guardduty'}
        )
        formatted_event = list(instance.reformat_msg(event))
        mock_reformat.assert_called_once()
        assert [event] == formatted_event
