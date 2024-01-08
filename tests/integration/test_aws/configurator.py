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

# Local imports
from .utils import TEST_DATA_PATH, TEMPLATE_DIR, TEST_CASES_DIR


# Classes
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

    def __init__(self):
        self.module = None
        self._metadata = None
        self._cases_ids = None
        self._test_configuration_template = None
        self._set_session_id()

    @property
    def module(self):
        return self.module

    @module.setter
    def module(self, test_module: str):
        self.module = test_module

    @property
    def metadata(self):
        return self._metadata

    @metadata.setter
    def metadata(self, value):
        self._metadata = value

    @property
    def cases_ids(self):
        return self._cases_ids

    @cases_ids.setter
    def cases_ids(self, value):
        self._cases_ids = value

    def _set_session_id(self) -> None:
        """Create and set the test session id."""
        self._session_id = str(uuid4())[:8]
        print(f"This test session id is: {self._session_id}")

    def configure_test(self, configuration_file="", cases_file="") -> None:
        """
        Configure and manage the resources for the test.

        Params
        ------
        - configuration_file (str): The name of the configuration file.
        - cases_file (str): The name of the test cases file.
        """
        # Set configuration path
        configuration_path = join(TEST_DATA_PATH, TEMPLATE_DIR, self.module)

        # Set test cases yaml path
        cases_yaml_path = join(TEST_DATA_PATH, TEST_CASES_DIR, self.module, cases_file)

        # Backup test data file
        backup_test_file = modify_file(test_data_path=cases_yaml_path)

        # Modify original file
        resources = self._modify_original_file(test_data_path=cases_yaml_path)

        # Create resources for test
        self._create_resources(resources=resources)

        # Set test cases data
        parameters, self._metadata, self._cases_ids = get_test_cases_data(cases_yaml_path)

        # Set test configuration template for tests with config files
        self._set_configuration_template(configuration_file=configuration_file,
                                         parameters=parameters)

        yield

        # Delete resources
        self._delete_resources(resources=resources)

        # Restore original file
        restore_original_file(test_data_path=cases_yaml_path,
                              backup_file=backup_test_file)

    def _modify_original_file(self, test_data_path: str) -> set:
        """Add session id to original yaml file resource name

        Returns
        -------
        - resources (set): Set containing resources to create.
        """
        resources = set()
        # Read and Modify the cases yaml file
        with open(test_data_path, 'w') as file:
            lines = file.readlines()  # Read all lines from the file

            for line in lines:
                if 'BUCKET_NAME' in line or 'bucket_name' in line:
                    # Extract the bucket name, modify it, and write the modified line
                    parts = line.split(':')
                    if len(parts) > 1:
                        bucket_name = parts[1].strip() + self._session_id
                        resources.add(bucket_name)  # Add only the modified bucket name to the set
                        modified_line = parts[0] + ': ' + bucket_name + '\n'
                    else:
                        modified_line = line
                    file.write(modified_line)
                else:
                    file.write(line)

            file.truncate()  # Truncate the file to the current position to remove any leftover content

        return resources

    def _set_configuration_template(self, configuration_file: str, parameters: str) -> None:
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
            self.test_configuration_template = load_configuration_template(
                configuration_path,
                parameters,
                self._metadata
            )

    def _create_resources(self, resources: set) -> None:
        """Create AWS resources for test execution

         Parameters
         ----------
         - resources (set): Set containing resources to create.

         """
        pass

    def _delete_resources(self, resources):
        pass


def modify_file(test_data_path: str) -> str:
    """Backup test data file and modify it

    Parameters
    ----------
    - test_data_path (str): Path of the original test file

    """
    with open(test_data_path, 'r') as original_file:
        backup_content = original_file.read()
        return backup_content


def restore_original_file(test_data_path: str, backup_file: str) -> None:
    """Restore file to original state.

    Parameters
    ----------
    - test_data_path (str): Path of test file.

    - backup_file (str): Backup test file.

    """
    with open(test_data_path, 'w') as original_file:
        # Write the original content back to the file
        original_file.write(backup_file)


# Instantiate configurator
configurator = TestConfigurator()
