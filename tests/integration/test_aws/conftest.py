# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contain all necessary components (fixtures, classes, methods) to configure the test for its execution.
"""

import pytest
from time import time
from botocore.exceptions import ClientError
from uuid import uuid4

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
    generate_file,
    create_sqs_queue,
    get_sqs_queue_arn,
    set_sqs_policy,
    set_bucket_event_notification_configuration,
    delete_sqs_queue,
    delete_bucket_files
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


"""Session fixtures"""


@pytest.fixture(scope="session", autouse=True)
def buckets_manager():
    """Initializes a set to manage the creation and deletion of the buckets used throughout the test session.

    Yields
    ------
    buckets : set
        Set of buckets
    """
    # Create buckets set
    buckets: set = set()

    yield buckets

    # Delete all buckets created during execution
    for bucket in buckets:
        try:
            # Delete the bucket
            delete_bucket(bucket_name=bucket)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting bucket, delete manually",
                "resource_name": bucket,
                "error": str(error)
            })

        except Exception as error:
            logger.error({
                "message": "Broad error deleting bucket, delete manually",
                "resource_name": bucket,
                "error": str(error)
            })


@pytest.fixture(scope="session", autouse=True)
def log_groups_manager():
    """Initializes a set to manage the creation and deletion of the log groups used throughout the test session.

    Yields
    ------
    log_groups : set
        Set of log groups.
    """
    # Create log groups set
    log_groups: set = set()

    yield log_groups

    # Delete all resources created during execution
    for log_group in log_groups:
        try:
            delete_log_group(log_group_name=log_group)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting log_group, delete manually",
                "resource_name": log_group,
                "error": str(error)
            })
            raise

        except Exception as error:
            logger.error({
                "message": "Broad error deleting log_group, delete manually",
                "resource_name": log_group,
                "error": str(error)
            })


@pytest.fixture(scope="session", autouse=True)
def sqs_manager():
    """Initializes a set to manage the creation and deletion of the sqs queues used throughout the test session.

    Yields
    ------
    buckets : set
        Set of SQS queues
    """
    # Create buckets set
    sqs_queues: set = set()

    yield sqs_queues

    # Delete all resources created during execution
    for sqs in sqs_queues:
        try:
            delete_sqs_queue(sqs_queue_url=sqs)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting sqs queue, delete manually",
                "resource_name": sqs,
                "error": str(error)
            })

        except Exception as error:
            logger.error({
                "message": "Broad error deleting sqs queue, delete manually",
                "resource_name": sqs,
                "error": str(error)
            })


"""S3 fixtures"""


@pytest.fixture()
def create_test_bucket(buckets_manager,
                       metadata: dict):
    """Create a bucket.

    Parameters
    ----------
    buckets_manager : fixture
        Set of buckets.
    metadata : dict
        Bucket information.

    """
    bucket_name = metadata["bucket_name"]
    bucket_type = metadata["bucket_type"]

    try:
        # Create bucket
        create_bucket(bucket_name=bucket_name)
        logger.debug(f"Created new bucket: type {bucket_name}")

        # Append created bucket to resource set
        buckets_manager.add(bucket_name)

    except ClientError as error:
        logger.error({
            "message": "Client error creating bucket",
            "bucket_name": bucket_name,
            "bucket_type": bucket_type,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating bucket",
            "bucket_name": bucket_name,
            "bucket_type": bucket_type,
            "error": str(error)
        })
        raise


@pytest.fixture
def manage_bucket_files(metadata: dict):
    """Upload a file to S3 bucket and delete after the test ends.

    Parameters
    ----------
    metadata : dict
        Metadata to get the parameters.
    """
    # Get bucket name
    bucket_name = metadata['bucket_name']

    # Get bucket type
    bucket_type = metadata['bucket_type']

    # Generate file
    data, key = generate_file(bucket_type=bucket_type,
                                   bucket_name=bucket_name)

    try:
        # Upload file to bucket
        upload_bucket_file(bucket_name=bucket_name,
                           data=data,
                           key=key)

        logger.debug('Uploaded file: %s to bucket "%s"', key, bucket_name)

        # Set filename for test execution
        metadata['uploaded_file'] = key

    except ClientError as error:
        logger.error({
            "message": "Client error uploading file to bucket",
            "bucket_name": bucket_name,
            "filename": key,
            "error": str(error)
        })
        raise error

    except Exception as error:
        logger.error({
            "message": "Broad error uploading file to bucket",
            "bucket_name": bucket_name,
            "filename": key,
            "error": str(error)
        })
        raise error

    yield

    try:
        # Delete all bucket files
        delete_bucket_files(bucket_name=bucket_name)
    except ClientError as error:
        logger.error({
            "message": "Client error deleting files in bucket",
            "bucket_name": bucket_name,
            "filename": key,
            "error": str(error)
        })
        raise error

    except Exception as error:
        logger.error({
            "message": "Broad error deleting files in bucket",
            "bucket_name": bucket_name,
            "filename": key,
            "error": str(error)
        })
        raise error


"""CloudWatch fixtures"""


@pytest.fixture()
def create_test_log_group(log_groups_manager,
                          metadata: dict) -> None:
    """Create a bucket.

    Parameters
    ----------
    log_groups_manager : fixture
        Log groups set.
    metadata : dict
        Log group information.
    """
    # Get log group name
    log_group_name = metadata["log_group_name"]

    try:
        # Create log group
        create_log_group(log_group_name=log_group_name)
        logger.debug(f"Created log group: {log_group_name}")

        # Append created bucket to resource list
        log_groups_manager.add(log_group_name)

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


"""SQS fixtures"""


@pytest.fixture
def set_test_sqs_queue(metadata: dict, sqs_manager):
    """Create a test sqs group

    Parameters
    ----------
    metadata : dict
        The metadata for the sqs queue.
    sqs_manager: fixture
        The SQS set for the test.

    Returns
    -------
    """
    # Get bucket name
    bucket_name = metadata["bucket_name"]
    # Get SQS name
    sqs_name = metadata["sqs_name"]

    try:
        # Create SQS and get URL
        sqs_queue_url = create_sqs_queue(sqs_name=sqs_name)
        # Add it to sqs set
        sqs_manager.add(sqs_queue_url)

        # Get SQS Queue ARN
        sqs_queue_arn = get_sqs_queue_arn(sqs_url=sqs_queue_url)

        # Set policy
        set_sqs_policy(bucket_name=bucket_name,
                       sqs_queue_url=sqs_queue_url,
                       sqs_queue_arn=sqs_queue_arn)

        # Set bucket notification configuration
        set_bucket_event_notification_configuration(bucket_name=bucket_name,
                                                    sqs_queue_arn=sqs_queue_arn)

    except ClientError as error:
        # Check if the sqs exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"SQS Queue {sqs_name} already exists")
            pass
        else:
            raise error

    except Exception as error:
        raise error


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
