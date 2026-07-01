# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contains all necessary components (fixtures, classes, methods) to configure the test for its execution.
"""

import os
import pytest
import boto3
from botocore.exceptions import ClientError

# qa-integration-framework imports
from wazuh_testing.logger import logger
from wazuh_testing.modules.aws.utils import (
    upload_log_events,
    create_log_group,
    create_log_stream,
    delete_bucket,
    delete_log_group,
    delete_log_stream,
    delete_s3_db,
    delete_services_db,
    upload_bucket_file,
    generate_file,
    create_sqs_queue,
    get_sqs_queue_arn,
    set_sqs_policy,
    set_bucket_event_notification_configuration,
    delete_sqs_queue,
    delete_bucket_file
)
from wazuh_testing.utils.services import control_service
from wazuh_testing.constants.aws import US_EAST_1_REGION

# Keys permanently seeded by DevOps in the shared bucket that tests must never delete.
_PERMANENT_SEED_KEYS = frozenset({
    'AWSLogs/819751203818/CloudTrail/us-east-1/2022/11/20/'
    '819751203818_CloudTrail_us-east-1_20221120T0000Z_372406355707169122.json',
})
# VPC permanent seed is identified by this flow-log-ID substring in its S3 key.
_PERMANENT_SEED_FLOW_LOG_IDS = frozenset({'fl-0754d951c16f517fa'})


def _safe_delete_key(key, bucket_name, s3_client):
    """Delete one key from the shared bucket; log failures; refuse to touch permanent seeds."""
    if key in _PERMANENT_SEED_KEYS or any(fid in key for fid in _PERMANENT_SEED_FLOW_LOG_IDS):
        logger.warning("TEARDOWN: skipping permanent seed key: %s", key)
        return
    try:
        delete_bucket_file(filename=key, bucket_name=bucket_name, client=s3_client)
        logger.debug("TEARDOWN: deleted key: %s", key)
    except ClientError as exc:
        logger.warning("TEARDOWN: failed to delete key %s from bucket %s: %s", key, bucket_name, exc)
    except Exception as exc:
        logger.warning("TEARDOWN: failed to delete key %s from bucket %s: %s", key, bucket_name, exc)


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


"""Boto3 client fixtures"""
# Use the environment variable or default to 'dev'
aws_profile = os.environ.get("AWS_PROFILE", "default")


@pytest.fixture()
def boto_session():
    """Create a boto3 Session using the system defined AWS profile."""
    return boto3.Session(profile_name=f'{aws_profile}')


@pytest.fixture()
def s3_client(boto_session: boto3.Session):
    """Create an S3 client to manage bucket resources.

    Args:
        boto_session (boto3.Session): Session used to create the client.

    Returns:
        boto3.resources.base.ServiceResource: S3 client to manage bucket resources.
    """
    return boto_session.resource(service_name="s3", region_name=US_EAST_1_REGION)


@pytest.fixture()
def ec2_client(boto_session: boto3.Session):
    """Create an EC2 client to manage VPC resources.

    Args:
        boto_session (boto3.Session): Session used to create the client.

    Returns:
        Service client instance: EC2 client to manage VPC resources.
    """
    return boto_session.client(service_name="ec2", region_name=US_EAST_1_REGION)


@pytest.fixture()
def logs_clients(boto_session: boto3.Session, metadata: dict):
    """Create CloudWatch Logs clients per region to manage CloudWatch resources.

    Args:
        boto_session (boto3.Session): Session used to create the client.
        metadata (dict): Metadata from the module to obtain the defined regions.

    Returns:
        list(Service client instance): CloudWatch client list to manage the service's resources in multiple regions.
    """
    # A client for each region is required to generate logs accordingly
    return [boto_session.client(service_name="logs", region_name=region)
            for region in metadata.get('regions', US_EAST_1_REGION).split(',')]


@pytest.fixture()
def sqs_client(boto_session: boto3.Session):
    """Create an SQS client to manage queues.

    Args:
        boto_session (boto3.Session): Session used to create the client.

    Returns:
        Service client instance: SQS client to manage the queue resources.
    """
    return boto_session.client(service_name="sqs", region_name=US_EAST_1_REGION)


"""Session fixtures"""


@pytest.fixture()
def buckets_manager(s3_client):
    """Initializes a set to manage the creation and deletion of the buckets used throughout the test session.

    Args:
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage the bucket resources.

    Yields:
        buckets (set): Set of buckets.
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage the bucket resources.
    """
    # Create buckets set
    buckets: set = set()

    yield buckets, s3_client

    # Delete all buckets created during execution
    for bucket in buckets:
        try:
            # Delete the bucket
            delete_bucket(bucket_name=bucket, client=s3_client)
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


@pytest.fixture()
def log_groups_manager(logs_clients):
    """Initializes a set to manage the creation and deletion of the log groups used throughout the test session.

    Args:
        logs_clients (list(Service client instance)): CloudWatch Logs client list to manage the CloudWatch resources.

    Yields:
        log_groups (set): Set of log groups.
        logs_clients (list(Service client instance)): CloudWatch Logs client list to manage the CloudWatch resources.
    """
    # Create log groups set
    log_groups: set = set()

    yield log_groups, logs_clients

    # Delete all resources created during execution
    for log_group in log_groups:
        try:
            for logs_client in logs_clients:
                delete_log_group(log_group_name=log_group, client=logs_client)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting log_group, delete manually",
                "resource_name": log_group,
                "error": str(error)
            })
            raise error

        except Exception as error:
            logger.error({
                "message": "Broad error deleting log_group, delete manually",
                "resource_name": log_group,
                "error": str(error)
            })
            raise error


@pytest.fixture()
def sqs_manager(sqs_client):
    """Initializes a set to manage the creation and deletion of the sqs queues used throughout the test session.

    Args:
        sqs_client (Service client instance): SQS client to manage the SQS resources.

    Yields:
        sqs_queues (set): Set of SQS queues.
        sqs_client (Service client instance): SQS client to manage the SQS resources.
    """
    # Create buckets set
    sqs_queues: set = set()

    yield sqs_queues, sqs_client

    # Delete all resources created during execution
    for sqs in sqs_queues:
        try:
            delete_sqs_queue(sqs_queue_url=sqs, client=sqs_client)
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
def test_configuration() -> dict:
    """Fallback for tests that do not parametrize test_configuration (e.g. multiple-calls tests).
    Parametrize overrides this fixture, so tests that do supply test_configuration still work.
    """
    return {}


@pytest.fixture()
def create_test_bucket(metadata: dict, test_configuration: dict):
    """Use a pre-existing S3 bucket for tests.

    Args:
        metadata (dict): Bucket information.
        test_configuration (dict): Wazuh configuration template built at import time.
            Patched in-place so set_wazuh_configuration writes the shared bucket into ossec.conf.
    """
    shared_bucket = os.environ.get('AWS_BUCKET_NAME')
    if not shared_bucket:
        raise EnvironmentError(
            "AWS_BUCKET_NAME is not set. A pre-existing S3 bucket is required. "
            "Set the IT_AWS_BUCKET_NAME GitHub secret."
        )
    # Preserve the original YAML bucket name so generate_file can resolve custom bucket types
    # (kms, macie, trusted_advisor) via bucket_name.split('-')[1] inside get_data_generator.
    metadata['original_bucket_name'] = metadata.get('bucket_name', shared_bucket)
    # Override so all S3 operations and the Wazuh module CLI use the shared bucket.
    metadata['bucket_name'] = shared_bucket

    # Patch test_configuration so set_wazuh_configuration writes the shared bucket into ossec.conf.
    # Without this, ossec.conf keeps the YAML name (plus the session suffix added by _modify_metadata),
    # causing a mismatch with metadata['bucket_name'] and triggering incorrect_parameters failures.
    for section in test_configuration.get('sections', []):
        for element in section.get('elements', []):
            bucket_cfg = element.get('bucket')
            if isinstance(bucket_cfg, dict):
                for bucket_elem in bucket_cfg.get('elements', []):
                    if 'name' in bucket_elem:
                        bucket_elem['name']['value'] = shared_bucket


@pytest.fixture
def manage_bucket_files(metadata: dict, s3_client, ec2_client):
    """Upload a file to S3 bucket and delete after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage the bucket resources.
        ec2_client (Service client instance): EC2 client to manage VPC resources.
    """
    # Get bucket name
    bucket_name = metadata['bucket_name']

    # Get bucket type
    bucket_type = metadata['bucket_type']

    # Get only_logs_after, regions, prefix and suffix if set to generate file accordingly
    file_creation_date = metadata.get('only_logs_after')
    regions = metadata.get('regions', US_EAST_1_REGION).split(',')
    prefix = metadata.get('path', '')
    suffix = metadata.get('path_suffix', '')

    # Check if the VPC type is the one to be tested
    vpc_bucket = bucket_type == 'vpcflow'

    # Check if logs need to be created
    log_number = metadata.get("expected_results", 1) > 0

    # Generate files
    # Use the original YAML bucket name for generate_file — the framework derives the
    # custom type (kms/macie/trusted) from bucket_name.split('-')[1], which breaks with
    # the shared bucket name. All actual S3 operations still use the shared bucket_name.
    data_bucket_name = metadata.get('original_bucket_name', bucket_name)
    uploaded_keys = []
    if log_number:
        files_to_upload = []
        metadata['uploaded_file'] = ''
        flow_log_id = None
        try:
            if vpc_bucket:
                vpc_id = os.environ.get('AWS_VPC_ID')
                if not vpc_id:
                    raise EnvironmentError(
                        "AWS_VPC_ID is not set. A pre-existing VPC ID is required "
                        "for VPC flow log tests. Set the IT_AWS_VPC_ID GitHub secret."
                    )
                response = ec2_client.create_flow_logs(
                    ResourceIds=[vpc_id],
                    ResourceType='VPC',
                    TrafficType='REJECT',
                    LogDestinationType='s3',
                    LogDestination=f'arn:aws:s3:::{bucket_name}'
                )
                unsuccessful = response.get('Unsuccessful', [])
                if unsuccessful:
                    err = unsuccessful[0]['Error']
                    raise RuntimeError(
                        f"Failed to create VPC flow log on {vpc_id}: "
                        f"[{err['Code']}] {err['Message']}"
                    )
                flow_log_id = response['FlowLogIds'][0]
                metadata['flow_log_id'] = flow_log_id
                for region in regions:
                    data, key = generate_file(bucket_type=bucket_type,
                                              bucket_name=data_bucket_name,
                                              date=file_creation_date,
                                              region=region,
                                              prefix=prefix,
                                              suffix=suffix,
                                              flow_log_id=flow_log_id)
                    files_to_upload.append((data, key))
            else:
                for region in regions:
                    data, key = generate_file(bucket_type=bucket_type,
                                              bucket_name=data_bucket_name,
                                              region=region,
                                              prefix=prefix,
                                              suffix=suffix,
                                              date=file_creation_date)
                    files_to_upload.append((data, key))

            for data, key in files_to_upload:
                # Upload file to bucket
                upload_bucket_file(bucket_name=bucket_name,
                                   data=data,
                                   key=key,
                                   client=s3_client)

                logger.debug('Uploaded file: %s to bucket "%s"', key, bucket_name)

                # Set filename for test execution
                metadata['uploaded_file'] += key
                uploaded_keys.append(key)

        except ClientError as error:
            logger.error({
                "message": "Client error uploading file to bucket",
                "bucket_name": bucket_name,
                "error": str(error)
            })
            if flow_log_id is not None:
                try:
                    ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
                except Exception:
                    pass
            raise error

        except Exception as error:
            logger.error({
                "message": "Broad error uploading file to bucket",
                "bucket_name": bucket_name,
                "error": str(error)
            })
            if flow_log_id is not None:
                try:
                    ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
                except Exception:
                    pass
            raise error

    yield

    if log_number:
        # Collect every key this fixture or the test body uploaded.
        all_keys = list(uploaded_keys)
        extra_key = metadata.get('filename')
        if extra_key and extra_key not in uploaded_keys:
            all_keys.append(extra_key)

        for key in all_keys:
            _safe_delete_key(key, bucket_name, s3_client)

        if vpc_bucket and flow_log_id is not None:
            try:
                ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
            except Exception as exc:
                logger.warning("TEARDOWN: failed to delete flow log %s: %s", flow_log_id, exc)


"""CloudWatch fixtures"""


@pytest.fixture()
def create_test_log_group(log_groups_manager,
                          metadata: dict) -> None:
    """Create a log group.

    Args:
        log_groups_manager (tuple): Log groups set and CloudWatch clients.
        metadata (dict): Log group information.
    """
    # Get log group names
    log_group_names = metadata["log_group_name"].split(',')

    # If the resource_type is defined, then the resource must be created
    resource_creation = 'resource_type' in metadata

    log_groups, logs_clients = log_groups_manager

    try:
        if resource_creation:
            # Create log group
            for log_group in log_group_names:
                for logs_client in logs_clients:
                    create_log_group(log_group_name=log_group, client=logs_client)
                    logger.debug(f"Created log group: {log_group}")

                # Append created log group to resource list
                log_groups.add(log_group)

    except ClientError as error:
        logger.error({
            "message": "Client error creating log group",
            "log_group": log_group,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating log group",
            "log_group": log_group,
            "error": str(error)
        })
        raise


@pytest.fixture()
def create_test_log_stream(metadata: dict, log_groups_manager) -> None:
    """Create a log stream.

    Args:
        metadata (dict): Log group information.
        log_groups_manager (tuple): Log groups set and CloudWatch clients.
    """
    # Get log group names
    log_group_names = metadata["log_group_name"].split(',')

    # Get log stream
    log_stream_name = metadata['log_stream_name']

    # If the resource_type is defined, then the resource must be created
    resource_creation = 'resource_type' in metadata

    _, logs_clients = log_groups_manager

    try:
        if resource_creation:
            # Create log stream for each log group defined
            for log_group in log_group_names:
                for logs_client in logs_clients:
                    create_log_stream(log_group=log_group,
                                      log_stream=log_stream_name,
                                      client=logs_client)
                    logger.debug(f'Created log stream {log_stream_name} within log group {log_group}')

    except ClientError as error:
        logger.error({
            "message": "Client error creating log stream",
            "log_group": log_group,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating log stream",
            "log_group": log_group,
            "error": str(error)
        })
        raise


@pytest.fixture
def manage_log_group_events(metadata: dict, logs_clients):
    """Upload events to a log stream inside a log group and delete the log stream after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
        logs_clients (list(Service client instance)): CloudWatch Logs client list to manage the CloudWatch resources.
    """
    # Get log group names
    log_group_names = metadata["log_group_name"].split(',')

    # Get log stream name
    log_stream_name = metadata["log_stream_name"]

    # Get number of events
    event_number = metadata.get("expected_results", 1)

    # If the resource_type is defined, then the resource must be created
    resource_creation = 'resource_type' in metadata

    try:
        if resource_creation:
            log_creation_date = metadata.get('only_logs_after')
            for log_group in log_group_names:
                for logs_client in logs_clients:
                    # Create log events in log group
                    upload_log_events(
                        log_stream=log_stream_name,
                        log_group=log_group,
                        date=log_creation_date,
                        type_json='discard_field' in metadata,
                        events_number=event_number,
                        client=logs_client
                    )

    except ClientError as error:
        logger.error({
            "message": "Client error uploading events to log stream",
            "log_group": log_group,
            "log_stream_name": log_stream_name,
            "error": str(error)
        })
        raise error

    except Exception as error:
        logger.error({
            "message": "Broad error uploading events to log stream",
            "log_group": log_group,
            "log_stream_name": log_stream_name,
            "error": str(error)
        })
        raise error

    yield


"""SQS fixtures"""


@pytest.fixture
def set_test_sqs_queue(metadata: dict, sqs_manager, s3_client) -> None:
    """Create a test SQS queue.

    Args:
        metadata (dict): The metadata for the SQS queue.
        sqs_manager (fixture): The SQS set for the test.
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage bucket resources.
    """
    # Get bucket name
    bucket_name = metadata["bucket_name"]
    # Get SQS name
    sqs_name = metadata["sqs_name"]

    sqs_queues, sqs_client = sqs_manager

    try:
        # Create SQS and get URL
        sqs_queue_url = create_sqs_queue(sqs_name=sqs_name, client=sqs_client)
        # Add it to sqs set
        sqs_queues.add(sqs_queue_url)

        # Get SQS Queue ARN
        sqs_queue_arn = get_sqs_queue_arn(sqs_url=sqs_queue_url, client=sqs_client)

        # Set policy
        set_sqs_policy(bucket_name=bucket_name,
                       sqs_queue_url=sqs_queue_url,
                       sqs_queue_arn=sqs_queue_arn,
                       client=sqs_client)

        # Set bucket notification configuration
        set_bucket_event_notification_configuration(bucket_name=bucket_name,
                                                    sqs_queue_arn=sqs_queue_arn,
                                                    client=s3_client)

    except ClientError as error:
        # Check if the sqs exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"SQS Queue {sqs_name} already exists")
            raise error
        else:
            raise error

    except Exception as error:
        raise error


"""DB fixtures"""


@pytest.fixture
def clean_s3_cloudtrail_db():
    """Delete the DB file before and after the test execution."""
    delete_s3_db()

    yield

    delete_s3_db()


@pytest.fixture
def clean_aws_services_db():
    """Delete the DB file before and after the test execution."""
    delete_services_db()

    yield

    delete_services_db()
