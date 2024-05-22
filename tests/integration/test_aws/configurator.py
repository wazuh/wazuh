# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    This file contains the Test Configurator class that will manage all resources and configurations for each test
    module.
"""
from os.path import join
from uuid import uuid4

# qa-integration-framework imports
from wazuh_testing.utils.configuration import (
    get_test_cases_data,
    load_configuration_template,
)
from wazuh_testing.logger import logger


# Local imports
from .utils import TEST_DATA_PATH, TEMPLATE_DIR, TEST_CASES_DIR

# Constants
METADATA_SQS = 'sqs_name'
METADATA_RESOURCE_TYPE = 'resource_type'
METADATA_BUCKET = 'bucket_name'
METADATA_VPC = 'vpc_name'
METADATA_LOG_GROUP = 'log_group_name'
METADATA_LOG_STREAM = 'log_stream_name'

CONFIG_SQS = 'SQS_NAME'
CONFIG_BUCKET = 'BUCKET_NAME'
CONFIG_LOG_GROUP = 'LOG_GROUP_NAME'


# Classes
class TestConfigurator:
    """
    TestConfigurator class is responsible for configuring test data and parameters for a specific test module.

    Attributes:
    - module (str): The name of the test module.
    - metadata (list): Test metadata retrieved from the test cases.
    - cases_ids (list): Identifiers for the test cases.
    - test_configuration_template (list): The loaded configuration template for the test module.

    """

    def __init__(self):
        self._module = ""
        self._metadata: list = []
        self._cases_ids: list = []
        self._test_configuration_template: list = []
        self._set_session_id()

    @property
    def module(self):
        return self._module

    @module.setter
    def module(self, test_module: str):
        self._module = test_module

    @property
    def metadata(self):
        return self._metadata

    @property
    def test_configuration_template(self):
        return self._test_configuration_template

    @property
    def cases_ids(self):
        return self._cases_ids

    def _set_session_id(self) -> None:
        """Create and set the test session id."""
        self._session_id = str(uuid4())[:8]
        logger.info(f"This test session id is: {self._session_id}")

    def configure_test(self, configuration_file="", cases_file="") -> None:
        """Configure and manage the resources for the test.

        Args:
            configuration_file (str): The name of the configuration file.
            cases_file (str): The name of the test cases file.
        """
        # Set test cases yaml path
        cases_yaml_path = join(TEST_DATA_PATH, TEST_CASES_DIR, self.module, cases_file)

        # Set test cases data
        parameters, self._metadata, self._cases_ids = get_test_cases_data(cases_yaml_path)

        # Modify original data to include session information
        self._modify_metadata(parameters=parameters)

        # Set test configuration template for tests with config files
        self._load_configuration_template(configuration_file=configuration_file,
                                          parameters=parameters)

    def _load_configuration_template(self, configuration_file: str, parameters: str) -> None:
        """Set the configuration template of the test.

        Args:
            configuration_file (str): The name of the configuration file.
            parameters (str): The test parameters.
        """
        if configuration_file != "":
            # Set config path
            configuration_path = join(TEST_DATA_PATH, TEMPLATE_DIR, self.module, configuration_file)

            # load configuration template
            self._test_configuration_template = load_configuration_template(
                configuration_path,
                parameters,
                self._metadata
            )

    def _modify_metadata(self, parameters: list) -> None:
        """Modify raw data to add test session information.

        Args:
            parameters (list): The parameters of the test.
        """
        # Add Suffix (_todelete) to alert a safe deletion of resource in case of errors.
        suffix = f"-{self._session_id}-todelete"

        # Add suffix to metadata
        for param, data in zip(parameters, self._metadata):
            # Determine whether resource creation is required or not
            resource_creation_required = METADATA_RESOURCE_TYPE in data

            if resource_creation_required:
                try:
                    if METADATA_SQS in data:
                        data[METADATA_SQS] += suffix
                        param[CONFIG_SQS] += suffix

                    if data[METADATA_RESOURCE_TYPE] == "bucket":
                        data[METADATA_BUCKET] += suffix
                        if METADATA_VPC in data:
                            data[METADATA_VPC] += suffix
                        if CONFIG_BUCKET in param:
                            param[CONFIG_BUCKET] += suffix

                    elif data[METADATA_RESOURCE_TYPE] == "log_group":
                        if CONFIG_LOG_GROUP in param:
                            suffixed_log_groups = []
                            for log_group in data[METADATA_LOG_GROUP].split(','):
                                log_group += suffix
                                suffixed_log_groups.append(log_group)
                            data[METADATA_LOG_GROUP] = ','.join(suffixed_log_groups)
                            param[CONFIG_LOG_GROUP] = data[METADATA_LOG_GROUP]
                            if METADATA_LOG_STREAM in data:  # It is not present for basic or parser tests
                                data[METADATA_LOG_STREAM] += suffix

                except KeyError:
                    raise


# Instantiate configurator
configurator = TestConfigurator()
