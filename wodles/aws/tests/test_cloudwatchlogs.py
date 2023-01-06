import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_service
import cloudwatchlogs

TEST_LOG_GROUP = 'test_group'


@pytest.mark.parametrize('only_logs_after', [utils.TEST_ONLY_LOGS_AFTER, None])
@pytest.mark.parametrize('aws_log_groups', [TEST_LOG_GROUP, None])
@pytest.mark.parametrize('remove_log_streams', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_service.AWSService.__init__', side_effect=aws_service.AWSService.__init__)
def test_AWSCloudWatchLogs__init__(mock_aws_service, mock_sts_client, remove_log_streams, aws_log_groups, only_logs_after):
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs,
                                        remove_log_streams=remove_log_streams,
                                        aws_log_groups=aws_log_groups,
                                        only_logs_after=only_logs_after)

    mock_aws_service.assert_called_once()
    assert instance.log_group_list == ([group for group in aws_log_groups.split(",") if group != ""] if aws_log_groups else [])
    assert instance.remove_log_streams == remove_log_streams
    assert instance.only_logs_after_millis == (int(datetime.strptime(only_logs_after, '%Y%m%d').replace(
            tzinfo=timezone.utc).timestamp() * 1000) if only_logs_after else None)
    assert instance.default_date_millis == int(instance.default_date.timestamp() * 1000)

@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_alerts():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_remove_aws_log_stream():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_alerts_within_range():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_data_from_db():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_update_values():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_save_data_db():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_log_streams():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_purge_db():
    pass