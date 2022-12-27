import pytest
import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import umbrella


@patch('aws_bucket.AWSCustomBucket.__init__')
def test_CiscoUmbrella__init__(mock_custom_bucket):
    """Test if the instances of CiscoUmbrella are created properly."""
    instance = utils.get_mocked_bucket(class_=umbrella.CiscoUmbrella)
    assert not instance.check_prefix
    assert instance.date_format == '%Y-%m-%d'

    mock_custom_bucket.assert_called_once()

@pytest.mark.skip("Not implemented yet")
def test_CiscoUmbrella_load_information_from_file():
    pass

@pytest.mark.skip("Not implemented yet")
def test_CiscoUmbrella_marker_only_logs_after():
    pass
