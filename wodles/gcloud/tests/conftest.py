import os
from sys import path
import pytest
from unittest.mock import patch
from copy import deepcopy

path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
from buckets.bucket import WazuhGCloudBucket
from pubsub.subscriber import WazuhGCloudSubscriber


COMMON_PARAMETERS = [
    {'credentials_file': 'credentials.json'},
    {'logger': None},
]

GCLOUD_BUCKET_PARAMETERS = [
    COMMON_PARAMETERS + [
        {'bucket_name': 'test-bucket'},
        {'prefix': ''},
        {'delete_file': False},
        {'only_logs_after': None},
    ]
]

GCLOUD_PUBSUB_PARAMETERS = [
    COMMON_PARAMETERS + [
        {'project': 'wazuh-dev'},
        {'subscription_id': 'testing'},
    ]
]


data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                         'data/')


@pytest.fixture()
def test_data_path() -> str:
    """
    Fixture that returns the path where the tests data is at.

    Returns
    -------
    str
        Full path of the tests' data folder.
    """
    return deepcopy(data_path)


@pytest.fixture(params=deepcopy(GCLOUD_BUCKET_PARAMETERS))
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def gcloud_bucket(mock_client, request):
    """
    Return a WazuhGCloudBucket client.

    Parameters
    ----------
    mock_client : MagicMock
        Mocked GCP client.
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.

    Returns
    -------
    WazuhGCloudBucket
        Initialized client.
    """
    client = WazuhGCloudBucket(**{k: v for i in request.param for k, v in
                                  i.items()})
    return client


@pytest.fixture(params=deepcopy(GCLOUD_PUBSUB_PARAMETERS))
@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def gcloud_subscriber(mock_client, request):
    """
    Return a WazuhGCloudSubscriber client.

    Parameters
    ----------
    mock_client : MagicMock
        Mocked GCP client.
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test.

    Returns
    -------
    WazuhGCloudSubscriber
        Initialized subscriber.
    """
    client = WazuhGCloudSubscriber(**{k: v for i in request.param for k, v in
                                   i.items()})
    return client
