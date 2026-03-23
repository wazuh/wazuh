"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest

from wazuh_testing.modules.api.utils import add_resources, relate_resources, remove_resources


@pytest.fixture
def set_security_resources(test_metadata: dict) -> None:
    """Configure the security resources using the API and clean the added resources.

    Args:
        test_metadata (dict): Test metadata.
    """
    remove_resources(test_metadata)
    test_metadata = add_resources(test_metadata)
    relate_resources(test_metadata)

    yield

    remove_resources(test_metadata)
