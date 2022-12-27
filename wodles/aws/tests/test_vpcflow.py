import pytest
import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import vpcflow


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_AWSVPCFlowBucket__init__(mock_logs_bucket):
    """Test if the instances of CiscoUmbrella are created properly."""
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)
    assert instance.service == 'vpcflowlogs'

    mock_logs_bucket.assert_called_once()

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_load_information_from_file():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_get_ec2_client():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_get_flow_logs_ids():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_already_processed():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_get_days_since_today():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_get_date_list():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_get_date_last_log():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_iter_regions_and_accounts():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_db_count_region():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_db_maintenance():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_get_vpc_prefix():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_build_s3_filter_args():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_iter_files_in_bucket():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSVPCFlowBucket_mark_complete():
    pass
