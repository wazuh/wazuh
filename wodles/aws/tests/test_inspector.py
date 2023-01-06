import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_service
import inspector


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_service.AWSService.__init__', side_effect=aws_service.AWSService.__init__)
def test_AWSInspector__init__(mock_aws_service, mock_sts_client):
    instance = utils.get_mocked_service(class_=inspector.AWSInspector)

    mock_aws_service.assert_called_once()
    assert instance.retain_db_records == 5
    assert instance.sent_events == 0


@patch('aws_service.AWSService.__init__')
def test_AWSInspector_send_describe_findings(mock_aws_service):
    arn_list = ['arn1']

    instance = utils.get_mocked_service(class_=inspector.AWSInspector)

    mock_client = MagicMock()
    instance.client = mock_client
    instance.client.describe_findings.return_value = {
        'findings': [
            {
                'arn': 'arn1',
                'schemaVersion': 123,
                'service': 'string',
            }
        ]
    }
    with patch('wazuh_integration.WazuhIntegration.send_msg') as mock_send_msg, \
            patch('aws_service.AWSService.format_message') as mock_format:
        instance.send_describe_findings(arn_list)
        assert instance.sent_events == 1
        mock_send_msg.assert_called_once()
        mock_format.assert_called_once()


@pytest.mark.skip("Not implemented yet")
def test_AWSInspector_get_alerts():
    pass
