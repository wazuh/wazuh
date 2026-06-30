import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'services'))
import aws_service
import inspector

TEST_SERVICES_SCHEMA = 'schema_services_test.sql'


def mock_get_client(*args, **kwargs):
    mock_client = MagicMock()
    mock_client.list_findings.side_effect = [
        {
            'findings': [
                {'arn': 'arn1', 'schemaVersion': 123, 'service': 'inspector2'}
            ],
            'nextToken': 'tok1'
        },
        {
            'findings': [
                {'arn': 'arn2', 'schemaVersion': 123, 'service': 'inspector2'}
            ]
        }
    ]
    return mock_client


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_service.AWSService.__init__', side_effect=aws_service.AWSService.__init__)
def test_aws_inspector_initializes_properly(mock_aws_service, mock_sts_client):
    """Test if the instances of AWSInspector are created properly."""
    instance = utils.get_mocked_service(class_=inspector.AWSInspector)

    mock_aws_service.assert_called_once()
    assert instance.retain_db_records == 5
    assert instance.sent_events == 0


@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('only_logs_after', [utils.TEST_ONLY_LOGS_AFTER, None])
@patch('wazuh_integration.WazuhAWSDatabase.init_db')
@patch('wazuh_integration.WazuhAWSDatabase.close_db')
@patch('inspector.aws_tools.debug')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch.object(inspector.AWSInspector, 'get_client', mock_get_client)
def test_aws_inspector_get_alerts(mock_send_msg, mock_sts_client, mock_debug, mock_init_db, mock_close_db,
                                  only_logs_after, reparse, custom_database):
    """Test 'get_alerts' method sends the collected events and updates the DB accordingly."""
    utils.database_execute_script(custom_database, TEST_SERVICES_SCHEMA)

    instance = utils.get_mocked_service(class_=inspector.AWSInspector,
                                        reparse=reparse, only_logs_after=only_logs_after, region=utils.TEST_REGION)

    instance.account_id = utils.TEST_ACCOUNT_ID

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    instance.get_alerts()

    last_scan_date = utils.database_execute_query(custom_database,
                                                  instance.sql_find_last_scan.format(table_name=instance.db_table_name),
                                                  {
                                                      'service_name': instance.service_name,
                                                      'aws_account_id': instance.account_id,
                                                      'aws_region': instance.region}
                                                  )

    assert datetime.strptime(last_scan_date.split(' ')[0], "%Y-%m-%d").strftime("%Y%m%d") == datetime.now(timezone.utc).strftime(
        "%Y%m%d")


@pytest.mark.parametrize('region', inspector.INSPECTOR_V2_REGIONS)
@patch('wazuh_integration.WazuhAWSDatabase.init_db')
@patch('wazuh_integration.WazuhAWSDatabase.close_db')
@patch('inspector.aws_tools.debug')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch.object(inspector.AWSInspector, 'get_client', mock_get_client)
def test_aws_inspector_v2_get_alerts(mock_send_msg, mock_sts_client, mock_debug, mock_init_db, mock_close_db,
                                     region, custom_database):
    """Test 'get_alerts' for Inspector v2 to ensure proper handling."""
    utils.database_execute_script(custom_database, TEST_SERVICES_SCHEMA)

    instance = utils.get_mocked_service(class_=inspector.AWSInspector, region=region)
    instance.account_id = utils.TEST_ACCOUNT_ID

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    instance.get_alerts()

    last_scan_date = utils.database_execute_query(
        custom_database,
        instance.sql_find_last_scan.format(table_name=instance.db_table_name),
        {
            'service_name': instance.service_name,
            'aws_account_id': instance.account_id,
            'aws_region': instance.region
        }
    )
    assert datetime.strptime(last_scan_date.split(' ')[0], "%Y-%m-%d").strftime("%Y%m%d") == datetime.now(timezone.utc).strftime("%Y%m%d")


@patch('wazuh_integration.WazuhAWSDatabase.init_db')
@patch('wazuh_integration.WazuhAWSDatabase.close_db')
@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('inspector.aws_tools.debug')
def test_aws_inspector_v2_get_alerts_logs_no_findings_when_sent_events_v2_is_zero(
        mock_debug, mock_sts_client, mock_send_msg, mock_close_db, mock_init_db, custom_database):
    """Test get_alerts logs 'No findings' message when InspectorV2 returns 0 findings."""
    utils.database_execute_script(custom_database, TEST_SERVICES_SCHEMA)
    region = inspector.INSPECTOR_V2_REGIONS[-1]

    instance = utils.get_mocked_service(class_=inspector.AWSInspector, region=region)
    instance.account_id = utils.TEST_ACCOUNT_ID
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    v2_client = MagicMock()
    v2_client.list_findings.return_value = {'findings': []}

    with patch.object(instance, 'get_client', return_value=v2_client):
        instance.get_alerts()

    mock_debug.assert_any_call(
        f"+++ [InspectorV2] No findings with recent updates in the specified time range", 1)


@patch('wazuh_integration.WazuhAWSDatabase.init_db')
@patch('wazuh_integration.WazuhAWSDatabase.close_db')
@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('inspector.aws_tools.debug')
def test_aws_inspector_get_alerts_logs_no_new_events_when_nothing_sent(
        mock_debug, mock_sts_client, mock_send_msg, mock_close_db, mock_init_db, custom_database):
    """Test get_alerts logs 'no new events' when sent_events is 0 (V2 returns nothing)."""
    utils.database_execute_script(custom_database, TEST_SERVICES_SCHEMA)
    region = inspector.INSPECTOR_V2_REGIONS[0]

    instance = utils.get_mocked_service(class_=inspector.AWSInspector, region=region)
    instance.account_id = utils.TEST_ACCOUNT_ID
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    v2_client = MagicMock()
    v2_client.list_findings.return_value = {'findings': []}

    with patch.object(instance, 'get_client', return_value=v2_client):
        instance.get_alerts()

    mock_debug.assert_any_call(
        f'+++ There are no new events in the "{region}" region', 1)


@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('inspector.aws_tools.debug')
def test_aws_inspector_v2_get_alerts_inspector_v2_skips_event_matching_discard_field(
        mock_debug, mock_sts_client, mock_send_msg):
    """Test get_alerts_inspector_v2 skips a finding when event_should_be_skipped returns True."""
    instance = utils.get_mocked_service(
        class_=inspector.AWSInspector,
        region=inspector.INSPECTOR_V2_REGIONS[0],
        discard_field='severity',
        discard_regex='LOW'
    )

    v2_client = MagicMock()
    v2_client.list_findings.return_value = {
        'findings': [{'severity': 'LOW', 'findingArn': 'arn:low'}]
    }

    with patch.object(instance, 'get_client', return_value=v2_client):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        instance.get_alerts_inspector_v2(now, now)

    mock_send_msg.assert_not_called()
    mock_debug.assert_any_call(
        f'+++ [InspectorV2] The "LOW" regex found a match in the '
        f'"severity" field. The event will be skipped.', 2)
