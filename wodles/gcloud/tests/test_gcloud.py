# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for gcloud module."""

import os
import sys
from argparse import Namespace
from unittest.mock import patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
import gcloud


def get_wodle_config(integration_type: str, credentials_file: str = None, log_level: int = 1,
                     subscription: str = "subscription", project: str = 'project', max_messages: int = 100,
                     n_threads: int = 100, bucket_name: str = "test_bucket", prefix: str = "",
                     delete_file: bool = False, only_logs_after: str = None, reparse: bool = False) -> dict:
    """Return a dict containing every parameter for the different supported integration types. Used to simulate
    different ossec.conf configurations.

    Parameters
    ----------
    integration_type : str
        Determine the type of the integration. Current supported values: pubsub and access_logs
    credentials_file : str
        Path to credentials file.
    log_level : int
        The level of verbosity for the logger
    subscription : str
        Subscription ID.
    project : str
        The name of the project for a pubsub integration
    max_messages: int
        Maximum number of messages to retrieve.
    n_threads : int
        Number of threads used to process the pubsub messages
    bucket_name : str
        Name of the bucket to read the logs from.
    prefix : prefix
        Expected prefix for the logs. It can be used to specify the relative path where the logs are stored.
    delete_file : bool
        Indicate whether blobs should be deleted after being processed.
    only_logs_after : datetime
        Date after which obtain logs.
    reparse : bool
        Whether to parse already parsed logs or not

    Returns
    -------
    dict
        A dict containing the configuration parameters with their values
    """
    return {'integration_type': integration_type, 'credentials_file': credentials_file, 'log_level': log_level,
            'subscription_id': subscription, 'project': project, 'max_messages': max_messages, 'n_threads': n_threads,
            'bucket_name': bucket_name, 'prefix': prefix, 'delete_file': delete_file, 'only_logs_after': only_logs_after,
            'reparse': reparse}


@pytest.mark.parametrize('integration_type', ['pubsub', 'access_logs'])
@patch('gcloud.GCSAccessLogs')
@patch('gcloud.WazuhGCloudSubscriber')
@patch('gcloud.ThreadPoolExecutor')
@patch('gcloud.tools.get_stdout_logger')
@patch('gcloud.cpu_count', side_effect=TypeError)
def test_gcloud(mock_cpu_count, mock_logger, mock_threads, mock_subscriber, mock_access_logs, integration_type):
    """Test gcloud module run and exits without errors using valid configurations."""
    kwargs = get_wodle_config(integration_type=integration_type)
    with patch('tools.get_script_arguments', return_value=Namespace(**kwargs)), pytest.raises(SystemExit) as err:
        gcloud.main()
    assert err.type == SystemExit
    assert err.value.code == 0


@pytest.mark.parametrize('parameters, errcode', [
    ({'integration_type': 'type'}, 1002),
    ({'integration_type': 'access_logs', 'bucket_name': ''}, 1103),
    ({'integration_type': 'pubsub', 'subscription': None}, 1200),
    ({'integration_type': 'pubsub', 'project': None}, 1201),
    ({'integration_type': 'pubsub', 'n_threads': 0}, 1202),
    ({'integration_type': 'pubsub', 'max_messages': 0}, 1203),
    ({'integration_type': 'pubsub', 'n_threads': None}, 999)
])
@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
@patch('pubsub.subscriber.WazuhGCloudSubscriber.check_permissions')
@patch('pubsub.subscriber.WazuhGCloudSubscriber.process_messages')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
@patch('buckets.access_logs.GCSAccessLogs.process_data', return_value=0)
@patch('gcloud.tools.get_stdout_logger')
def test_gcloud_ko(mock_logger, mock_data, mock_json, mock_messages, mock_permissions, mock_file, parameters, errcode):
    """Test gcloud module aborts its execution when called with invalid parameters."""
    kwargs = get_wodle_config(**parameters)
    with patch('tools.get_script_arguments', return_value=Namespace(**kwargs)), pytest.raises(SystemExit) as err:
        gcloud.main()
    assert err.type == SystemExit
    assert err.value.code == errcode
