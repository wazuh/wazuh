import pytest
import os
import sys
import re
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import server_access

@patch('aws_bucket.AWSCustomBucket.__init__')
def test_AWSServerAccess___init__(mock_custom_bucket):
    """Test if the instances of AWSServerAccess are created properly."""
    instance = utils.get_mocked_bucket(class_=server_access.AWSServerAccess)
    assert instance.date_regex == re.compile(r'(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})')
    assert instance.date_format == '%Y-%m-%d'

    mock_custom_bucket.assert_called_once()

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess__key_is_old():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess_iter_files_in_bucket():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess_marker_only_logs_after():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess_check_bucket():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess_load_information_from_file():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess_parse_line():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSServerAccess_merge_values():
    pass
