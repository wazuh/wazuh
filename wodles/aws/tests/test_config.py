import pytest
import os
import sys
from unittest.mock import patch
import re
from datetime import datetime, timedelta

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import config

@patch('aws_bucket.AWSLogsBucket.__init__')
def test_AWSConfigBucket__init__(mock_logs_bucket):
    """Test if the instances of AWSConfigBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    mock_logs_bucket.assert_called_once()
    assert instance.service == "Config"
    assert instance.field_to_load == "configurationItems"
    assert instance._leading_zero_regex == re.compile(r'/(0)(?P<num>\d)')
    assert instance._extract_date_regex == re.compile(r'\d{4}/\d{1,2}/\d{1,2}')


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_AWSConfigBucket_get_days_since_today(mock_logs_bucket):
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    test_date = "20220630"

    date = datetime.strptime(test_date, "%Y%m%d")
    delta = datetime.utcnow() - date + timedelta(days=1)

    assert instance.get_days_since_today(test_date) == delta.days

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_get_date_list():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_get_date_last_log():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_iter_regions_and_accounts():
    pass

# Extracted from the previous tests. To be reviewed/reworked
# @pytest.mark.parametrize('date, expected_date', [
#     ('2021/1/19', '20210119'),
#     ('2021/1/1', '20210101'),
#     ('2021/01/01', '20210101'),
#     ('2000/2/12', '20000212'),
#     ('2022/02/1', '20220201')
# ])
# def test_AWSConfigBucket__format_created_date(date: str, expected_date: str, aws_config_bucket):
#     """
#     Test AWSConfigBucket's format_created_date method.
#
#     Parameters
#     ----------
#     date : str
#         The date introduced.
#     expected_date : str
#         The date that the method should return.
#     aws_config_bucket : AWSConfigBucket
#         Instance of the AWSConfigBucket class.
#     """
#     assert aws_config_bucket._format_created_date(date) == expected_date

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket__remove_padding_zeros_from_marker():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_marker_only_logs_after():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_marker_custom_date():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_build_s3_filter_args():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_iter_files_in_bucket():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSConfigBucket_reformat_msg():
    pass
