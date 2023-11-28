# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contains all necessary components (fixtures, classes, methods)to configure the test for its execution.
"""

import pytest
from os.path import join

# qa-integration-framework imports
from wazuh_testing.logger import logger
from wazuh_testing.constants.aws import (
    FAKE_CLOUDWATCH_LOG_GROUP,
    PERMANENT_CLOUDWATCH_LOG_GROUP,
)
from wazuh_testing.modules.aws.utils import (
    create_log_events,
    create_log_group,
    create_log_stream,
    delete_log_group,
    delete_log_stream,
    delete_file,
    file_exists,
    upload_file
)
from wazuh_testing.modules.aws.utils import delete_s3_db, delete_services_db
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.configuration import (
    get_test_cases_data,
    load_configuration_template,
)
from wazuh_testing.modules.monitord import configuration as monitord_config

# Local imports
from .utils import TEST_DATA_PATH,  TEMPLATE_DIR, TEST_CASES_DIR, WAZUH_MODULES_DEBUG


# Set local internal options
local_internal_options = {WAZUH_MODULES_DEBUG: '2',
                          monitord_config.MONITORD_ROTATE_LOG: '0'}


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
    log_group_names = [item.strip() for item in metadata['log_group_name'].split(',')]
    for log_group_name in log_group_names:
        if log_group_name in SKIP_LOG_GROUP_CREATION:
            continue

        logger.debug('Creating log group: %s', log_group_name)
        create_log_group(log_group_name)
        log_stream = create_log_stream(log_group_name)
        logger.debug('Created log stream "%s" within log group "%s"', log_stream, log_group_name)
        create_log_events(
            log_stream=log_stream, log_group=log_group_name, event_number=metadata.get('expected_results', 1)
        )
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


class TestConfigurator:
    """
    TestConfigurator class is responsible for configuring test data and parameters for a specific test module.

    Attributes:
    - module (str): The name of the test module.
    - configuration_path (str): The path to the configuration directory for the test module.
    - test_cases_path (str): The path to the test cases directory for the test module.
    - metadata (list): Test metadata retrieved from the test cases.
    - parameters (list): Test parameters retrieved from the test cases.
    - cases_ids (list): Identifiers for the test cases.
    - test_configuration_template (list): The loaded configuration template for the test module.

    """
    def __init__(self, module):
        self.module = module
        self.configuration_path = join(TEST_DATA_PATH, TEMPLATE_DIR, self.module)
        self.test_cases_path = join(TEST_DATA_PATH, TEST_CASES_DIR, self.module)
        self.metadata = None
        self.parameters = None
        self.cases_ids = None
        self.test_configuration_template = None

    def configure_test(self, configuration_file="", cases_file=""):
        """
        Configures the test data and parameters for the given test module.

        Args:
        - configuration_file (str): The name of the configuration file.
        - cases_file (str): The name of the test cases file.

        Returns:
        None
        """
        # Set test cases path
        cases_path = join(self.test_cases_path, cases_file)

        # set test cases data
        self.parameters, self.metadata, self.cases_ids = get_test_cases_data(cases_path)

        # Set test configuration template for tests with config files
        if configuration_file != "":
            # Set config path
            configurations_path = join(self.configuration_path, configuration_file)

            # load configuration template
            self.test_configuration_template = load_configuration_template(
                configurations_path,
                self.parameters,
                self.metadata
            )
