# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    This file contain the Test Configurator class that will manage all resources and configurations for each test
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
        """
        Configure and manage the resources for the test.

        Params
        ------
        - configuration_file (str): The name of the configuration file.
        - cases_file (str): The name of the test cases file.
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
        """Set the configuration template of the test

        Params
        ------
        - configuration_file (str): The name of the configuration file.
        - parameters (str): The test parameters.

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
        """Modify raw data to add test session information

        Params
        ------
        - parameters (list): The parameters of the test.
        - metadata (list): The metadata of the test.
        """
        # Add Suffix (_todelete) to alert a safe deletion of resource in case of errors.
        suffix = f"-{self._session_id}-todelete"

        # Add suffix to metadata
        for param, data in zip(parameters, self._metadata):
            try:
                if "sqs_name" in data:
                    data["sqs_name"] += suffix
                    param["SQS_NAME"] += suffix

                if data["resource_type"] == "bucket":
                    data["bucket_name"] += suffix
                    if "BUCKET_NAME" in param:
                        param["BUCKET_NAME"] += suffix

                elif data["resource_type"] == "log_group":
                    param["LOG_GROUP_NAME"] += suffix
                    data["log_group_name"] += suffix

            except KeyError:
                raise


# Instantiate configurator
configurator = TestConfigurator()
