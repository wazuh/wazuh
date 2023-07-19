# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contain all necessary components (fixtures, classes, methods)to configure the test for its execution.
"""
import botocore
import pytest
from uuid import uuid4

# qa-integration-framework imports
from wazuh_testing.logger import logger
from wazuh_testing.constants.aws import (
    FAKE_CLOUDWATCH_LOG_GROUP,
    PERMANENT_CLOUDWATCH_LOG_GROUP,
)
from wazuh_testing.modules.aws.utils import (
    #create_bucket,
    create_log_events,
    create_log_group,
    create_log_stream,
    #delete_bucket,
    delete_log_group,
    delete_log_stream,
    delete_file,
    delete_s3_db,
    delete_services_db,
    file_exists,
    upload_file
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


# S3 fixtures

@pytest.fixture(scope="session", autouse=True)
def create_session_uuid():
    uuid = str(uuid4())[:8]
    return uuid


@pytest.fixture(scope="session", autouse=True)
def delete_buckets():
    bucket_list = []

    yield bucket_list

    for bucket in bucket_list:
        #delete_bucket(bucket)
        pass


@pytest.fixture()
def create_bucket(create_session_uuid, bucket_list, metadata):
    """

    Parameters
    ----------
        bucket_list
        create_session_uuid
        metadata

    Returns
    -------

    """
    bucket_name = metadata['bucket_name']
    bucket_name += f"-{create_session_uuid}"

    create_bucket(bucket_name=bucket_name)
    metadata['bucket_name'] = bucket_name

    yield

    bucket_list.append(bucket_name)

@pytest.fixture
def upload_and_delete_file_to_s3(metadata):
    """Upload a file to S3 bucket and delete after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
    """
    bucket_name = metadata['bucket_name']
    filename = upload_file(bucket_type=metadata['bucket_type'], bucket_name=metadata['bucket_name'])
    if filename != '':
        logger.debug('Uploaded file: %s to bucket "%s"', filename, bucket_name)
        metadata['uploaded_file'] = filename

    yield

    if file_exists(filename=filename, bucket_name=bucket_name):
        delete_file(filename=filename, bucket_name=bucket_name)
        logger.debug('Deleted file: %s from bucket %s', filename, bucket_name)


@pytest.fixture
def delete_file_from_s3(metadata):
    """Delete a file from S3 bucket after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
    """
    yield

    bucket_name = metadata['bucket_name']
    filename = metadata.get('filename')
    if filename is not None:
        delete_file(filename=filename, bucket_name=bucket_name)
        logger.debug('Deleted file: %s from bucket %s', filename, bucket_name)


# CloudWatch fixtures

@pytest.fixture(name='create_log_stream')
def fixture_create_log_stream(metadata):
    """Create a log stream with events and delete after the execution.

    Args:
        metadata (dict): Metadata to get the parameters.
    """

    SKIP_LOG_GROUP_CREATION = [PERMANENT_CLOUDWATCH_LOG_GROUP, FAKE_CLOUDWATCH_LOG_GROUP]
    print(PERMANENT_CLOUDWATCH_LOG_GROUP, FAKE_CLOUDWATCH_LOG_GROUP)
    log_group_names = [item.strip() for item in metadata['log_group_name'].split(',')]
    for log_group_name in log_group_names:
        if log_group_name in SKIP_LOG_GROUP_CREATION:
            continue

        import random
        log_group_name += f"-{random.randint(10**3, 10**4 - 1)}"

        logger.debug('Creating log group: %s', log_group_name)
        try:
            create_log_group(log_group_name)
        except botocore.ResourceAlreadyExistsException as e:
            pass
        log_stream = create_log_stream(log_group_name)
        logger.debug('Created log stream "%s" within log group "%s"', log_stream, log_group_name)
        try:
            create_log_events(
                log_stream=log_stream, log_group=log_group_name, event_number=metadata.get('expected_results', 1)
            )
        except botocore.errorfactory.ResourceAlreadyExistsException as e:
            pass
        except Exception as e:
            print(e)
            pass
        logger.debug('Created log events')
        metadata['log_stream'] = log_stream

    yield

    for log_group_name in log_group_names:
        if log_group_name in SKIP_LOG_GROUP_CREATION:
            continue
        delete_log_group(log_group_name)
        logger.debug('Deleted log group: %s', log_group_name)


@pytest.fixture
def create_log_stream_in_existent_group(metadata):
    """Create a log stream with events and delete after the execution.

    Args:
        metadata (dict): Metadata to get the parameters.
    """
    log_group_name = metadata['log_group_name']
    log_stream = create_log_stream(log_group_name)
    logger.debug('Created log stream "%s" within log group "%s"', log_stream, log_group_name)
    create_log_events(log_stream=log_stream, log_group=log_group_name)
    logger.debug('Created log events')
    metadata['log_stream'] = log_stream

    yield

    delete_log_stream(log_stream=log_stream, log_group=log_group_name)
    logger.debug('Deleted log stream: %s', log_stream)


@pytest.fixture(name='delete_log_stream')
def fixture_delete_log_stream(metadata):
    """Create a log stream with events and delete after the execution.

    Args:
        metadata (dict): Metadata to get the parameters.
    """
    yield
    log_stream = metadata['log_stream']
    delete_log_stream(log_stream=log_stream)
    logger.debug('Deleted log stream: %s', log_stream)
    

# DB fixtures
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
