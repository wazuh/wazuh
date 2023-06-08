'''
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest

from wazuh_testing.modules.api import configuration as api_configuration


@pytest.fixture(scope='module')
def add_configuration(configuration: list[dict], request: pytest.FixtureRequest):
    """Add configuration to the Wazuh API configuration files.

    Args:
        configuration (list[dict]): 
        request
    """
    configuration_types = ('base', 'security')
    test_target_types = []
    backups = {}

    # Define target files
    for type in configuration_types:
        if configuration.get(type, None):
            test_target_types.append(type)
            backups[type] = {}

    # Add configuration to the test target files
    for type in test_target_types:
        # Save current configuration
        backups[type] = api_configuration.get_configuration(configuration_type=type)
        # Set new configuration at the end of the configuration file
        api_configuration.append_configuration(configuration)

    yield

    # Restore target configuration files
    for type in test_target_types:
        api_configuration.append_configuration(backups[type])
        if type == 'security':
            api_configuration.delete_configuration_file(type)
