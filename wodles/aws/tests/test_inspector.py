# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils
import aws_constants as test_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'services'))
import aws_service
import inspector

TEST_SERVICES_SCHEMA = 'schema_services_test.sql'


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_service.AWSService.__init__', side_effect=aws_service.AWSService.__init__)
def test_aws_inspector_initializes_properly(mock_aws_service, mock_sts_client):
    """Test if the instances of AWSInspector are created properly."""
    instance = utils.get_mocked_service(class_=inspector.AWSInspector)

    mock_aws_service.assert_called_once()
    assert instance.retain_db_records == 5
    assert instance.sent_events == 0


@patch('aws_service.AWSService.get_sts_client')
def test_aws_inspector_send_describe_findings(mock_sts_client):
    """Test 'send_describe_findings' method sends the findings to Analysisd
    and updates the instance's sent_events attribute accordingly to the number of findings.
    """
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


@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('only_logs_after', [test_constants.TEST_ONLY_LOGS_AFTER, None])
@patch('wazuh_integration.WazuhAWSDatabase.init_db')
@patch('wazuh_integration.WazuhAWSDatabase.close_db')
@patch('inspector.AWSInspector.send_describe_findings')
@patch('inspector.aws_tools.debug')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
def test_aws_inspector_get_alerts(mock_sts_client, mock_debug, mock_send_describe_findings, mock_init_db, mock_close_db,
                                  only_logs_after, reparse, custom_database):
    """Test 'get_alerts' method sends the collected events and updates the DB accordingly.

    Parameters
    ----------
    reparse: bool
        Whether to parse already parsed logs or not.
    only_logs_after: str or None
        Date after which obtain logs.
    """
    utils.database_execute_script(custom_database, TEST_SERVICES_SCHEMA)

    instance = utils.get_mocked_service(class_=inspector.AWSInspector,
                                        reparse=reparse, only_logs_after=only_logs_after, region=test_constants.TEST_REGION)

    instance.account_id = test_constants.TEST_ACCOUNT_ID

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    instance.client = MagicMock()
    mock_list_findings = instance.client.list_findings
    mock_list_findings.side_effect = [{'findingArns': ['arn1'], 'nextToken': None},
                                      {'findingArns': ['arn2']}]

    instance.get_alerts()

    last_scan_date = utils.database_execute_query(custom_database,
                                                  instance.sql_find_last_scan.format(table_name=instance.db_table_name),
                                                  {
                                                      'service_name': instance.service_name,
                                                      'aws_account_id': instance.account_id,
                                                      'aws_region': instance.region}
                                                  )

    assert datetime.strptime(last_scan_date.split(' ')[0], "%Y-%m-%d").strftime("%Y%m%d") == datetime.utcnow().strftime(
        "%Y%m%d")
