import pytest
import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import load_balancers

@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSLBBucket__init__(mock_custom_bucket):
    """Test if the instances of AWSLBBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSLBBucket)
    assert instance.service == 'elasticloadbalancing'
    mock_custom_bucket.assert_called_once()


@patch('wazuh_integration.WazuhIntegration.__init__')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
@patch('aws_bucket.AWSCustomBucket.__init__', side_effect=aws_bucket.AWSCustomBucket.__init__)
def test_AWSLBBucket_get_base_prefix(mock_custom_bucket, mock_bucket, mock_sts, mock_integration):
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSLBBucket, prefix=f'{utils.TEST_PREFIX}/', suffix=f'{utils.TEST_SUFFIX}/')
    expected_base_prefix = f'{utils.TEST_PREFIX}/AWSLogs/{utils.TEST_SUFFIX}/'
    assert instance.get_base_prefix() == expected_base_prefix


@patch('load_balancers.AWSLBBucket.get_base_prefix', return_value='base_prefix/')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSLBBucket_get_service_prefix(mock_custom_bucket, mock_base_prefix):
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSLBBucket)
    expected_service_prefix = f'base_prefix/{utils.TEST_ACCOUNT_ID}/{instance.service}/'
    assert instance.get_service_prefix(utils.TEST_ACCOUNT_ID) == expected_service_prefix


@patch('aws_bucket.AWSBucket.iter_regions_and_accounts')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSLBBucket_iter_regions_and_accounts(mock_custom_bucket, mock_iter_regions_accounts):
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSLBBucket)
    instance.iter_regions_and_accounts(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)

    mock_iter_regions_accounts.assert_called_with(instance, utils.TEST_ACCOUNT_ID, utils.TEST_REGION)


@patch('load_balancers.AWSLBBucket.get_service_prefix', return_value=f'base_prefix/{utils.TEST_ACCOUNT_ID}/elasticloadbalancing/')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSLBBucket_get_full_prefix(mock_custom_bucket, mock_service_prefix):
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSLBBucket)
    expected_full_prefix = f'base_prefix/{utils.TEST_ACCOUNT_ID}/elasticloadbalancing/{utils.TEST_REGION}/'
    assert instance.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) == expected_full_prefix


@patch('aws_bucket.AWSBucket.mark_complete')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSLBBucket_mark_complete(mock_custom_bucket, mock_mark_complete):
    test_log_file = 'log_file'

    instance = utils.get_mocked_bucket(class_=load_balancers.AWSLBBucket)
    instance.mark_complete(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, test_log_file)

    mock_mark_complete.assert_called_with(instance, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, test_log_file)


@patch('load_balancers.AWSLBBucket.__init__')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSALBBucket__init__(mock_custom_bucket, mock_lb_bucket):
    """Test if the instances of AWSALBBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSALBBucket)
    mock_lb_bucket.assert_called_once()

@pytest.mark.skip("Not implemented yet")
def test_AWSALBBucket_load_information_from_file():
    pass


@patch('load_balancers.AWSLBBucket.__init__')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSCLBBucket__init__(mock_custom_bucket, mock_lb_bucket):
    """Test if the instances of AWSCLBBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSCLBBucket)
    mock_lb_bucket.assert_called_once()

@pytest.mark.skip("Not implemented yet")
def test_AWSCLBBucket_load_information_from_file():
    pass


@patch('load_balancers.AWSLBBucket.__init__')
@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSNLBBucket___init__(mock_custom_bucket, mock_lb_bucket):
    """Test if the instances of AWSNLBBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=load_balancers.AWSNLBBucket)
    mock_lb_bucket.assert_called_once()

@pytest.mark.skip("Not implemented yet")
def test_AWSNLBBucket_load_information_from_file():
    pass
