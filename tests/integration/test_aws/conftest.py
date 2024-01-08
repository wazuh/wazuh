# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contain all necessary components (fixtures, classes, methods) to configure the test for its execution.
"""
import pytest
from uuid import uuid4
from time import time
from botocore.exceptions import ClientError

# qa-integration-framework imports
from wazuh_testing.logger import logger
from wazuh_testing.modules.aws.utils import (
    create_bucket,
    upload_log_events,
    create_log_group,
    create_log_stream,
    delete_bucket,
    delete_log_group,
    delete_s3_db,
    delete_services_db,
    upload_bucket_file,
    delete_resources,
    generate_file
)
from wazuh_testing.utils.services import control_service


@pytest.fixture
def mark_cases_as_skipped(metadata):
    if metadata['name'] in ['alb_remove_from_bucket', 'clb_remove_from_bucket', 'nlb_remove_from_bucket']:
        pytest.skip(reason='ALB, CLB and NLB integrations are removing older logs from other region')


@pytest.fixture
def restart_wazuh_function_without_exception(daemon=None):
    """Restart all Wazuh daemons."""
    try:
        control_service("start", daemon=daemon)
    except ValueError:
        pass

    yield

    control_service('stop', daemon=daemon)


"""S3 fixtures"""


@pytest.fixture
def upload_file_to_bucket(metadata):
    """Upload a file to S3 bucket and delete after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
    """
    # Get bucket name
    bucket_name = metadata['bucket_name']

    # Get bucket type
    bucket_type = metadata['bucket_type']

    # Generate file
    data, filename = generate_file(bucket_type=bucket_type,
                                   bucket_name=bucket_name)

    try:
        # Upload file to bucket
        upload_bucket_file(bucket_name=bucket_name,
                           data=data,
                           filename=filename)

        logger.debug('Uploaded file: %s to bucket "%s"', filename, bucket_name)

        # Set filename for test execution
        metadata['uploaded_file'] = filename

    except ClientError as error:
        logger.error({
            "message": "Client error uploading file to bucket",
            "bucket_name": bucket_name,
            "filename": filename,
            "error": str(error)
        })
        pass

    except Exception as error:
        logger.error({
            "message": "Broad error uploading file to bucket",
            "bucket_name": bucket_name,
            "filename": filename,
            "error": str(error)
        })
        pass


"""CloudWatch fixtures"""


@pytest.fixture()
def create_test_log_group(create_session_id: str, create_and_delete_resources_list: list, metadata: dict):
    """Create a bucket.

    Parameters
    ----------
        create_session_id (str): Test session id.
        create_and_delete_resources_list (list): Resources list.
        metadata (dict): Log group information.

    Returns
    -------
        None
    """
    # Set variables from fixture
    test_session_id = create_session_id
    resources_list = create_and_delete_resources_list

    # Get log group information and add session id
    log_group_name = metadata["log_group_name"] + f"-{test_session_id}"

    try:
        # Create log group
        create_log_group(log_group_name=log_group_name)
        logger.debug(f"Created log group: {log_group_name}")

        # Create resource dict
        resource = {
            "type": "log_group",
            "name": log_group_name
        }

        # Append created log group to resources list
        resources_list.append(log_group_name)

    except ClientError as error:
        logger.error({
            "message": "Client error creating log group",
            "log_group": log_group_name,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating log group",
            "log_group": log_group_name,
            "error": str(error)
        })
        raise


@pytest.fixture()
def create_test_log_stream(metadata: dict):
    """Create a log stream.

    Parameters
    ----------
        metadata (dict): Log group information.

    Returns
    -------
        None
    """
    # Get log group
    log_group_name = metadata['log_group_name']

    # Create random stream name
    log_stream_name = str(uuid4())

    try:
        # Create log stream
        create_log_stream(log_group=log_group_name,
                          log_stream=log_stream_name)
        logger.debug(f'Created log stream {log_stream_name} within log group {log_group_name}')

        metadata['log_stream'] = log_stream_name

    except ClientError as error:
        logger.error({
            "message": "Client error creating log stream",
            "log_group": log_group_name,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating log stream",
            "log_group": log_group_name,
            "error": str(error)
        })
        raise


@pytest.fixture()
def create_test_events(metadata: dict):
    """Create a log event in a log stream.

    Parameters
    ----------
        metadata (dict): Log group information.

    Returns
    -------
        None
    """
    # Get log group name
    log_group_name = metadata["log_group_name"]

    # Get log stream name
    log_stream_name = metadata["log_stream_name"]

    # Get number of events
    event_number = metadata["expected_results"]

    # Generate event information
    events = [
        {'timestamp': int(time() * 1000), 'message': f"Test event number {i}"} for i in range(event_number)
    ]

    try:
        # Insert log events in log group
        upload_log_events(
            log_stream=log_stream_name,
            log_group=log_group_name,
            events=events
        )

    except ClientError as error:
        logger.error({
            "message": "Client error creating log stream",
            "log_group": log_group_name,
            "error": str(error)
        })
        pass

    except Exception as error:
        logger.error({
            "message": "Broad error creating log stream",
            "log_group": log_group_name,
            "error": str(error)
        })
        pass


"""DB fixtures"""


@pytest.fixture
def clean_s3_cloudtrail_db():
    """Delete the DB file before and after the test execution"""
    delete_s3_db()

    yield

    delete_s3_db()


@pytest.fixture
def clean_aws_services_db():
    """Delete the DB file before and after the test execution."""
    delete_services_db()

    yield

    delete_services_db()
