# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.constants.paths.variables import AGENTD_STATE 
from wazuh_testing.modules.agentd.configuration import AGENTD_INTERVAL
from wazuh_testing.utils import configuration

@pytest.fixture()
def remove_state_file() -> None:
    # Remove state file to check if agent behavior is as expected
    os.remove(AGENTD_STATE) if os.path.exists(AGENTD_STATE) else None

@pytest.fixture()
def set_state_interval(request: pytest.FixtureRequest, test_metadata) -> None:
    #import pdb; pdb.set_trace()
    #gg = request.param
    try:
        local_internal_options = request.param
    except AttributeError:
        try:
            local_internal_options = getattr(request.module, 'local_internal_options')
        except AttributeError:
            raise AttributeError('Error when using the fixture "configure_local_internal_options", no '
                                 'parameter has been passed explicitly, nor is the variable local_internal_options '
                                 'found in the module.') from AttributeError
        
    local_internal_options[AGENTD_INTERVAL] = test_metadata["interval"]
    
    yield

@pytest.fixture()
def configure_interval_local_internal_options(request: pytest.FixtureRequest, test_metadata) -> None:
    """Configure the local internal options file.

    Takes the `local_internal_options` variable from the request.
    The `local_internal_options` is a dict with keys and values as the Wazuh `local_internal_options` format.
    E.g.: local_internal_options = {'monitord.rotate_log': '0', 'syscheck.debug': '0' }

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    try:
        local_internal_options = request.param
    except AttributeError:
        try:
            local_internal_options = getattr(request.module, 'local_internal_options')
        except AttributeError:
            raise AttributeError('Error when using the fixture "configure_local_internal_options", no '
                                 'parameter has been passed explicitly, nor is the variable local_internal_options '
                                 'found in the module.') from AttributeError

    backup_local_internal_options = configuration.get_local_internal_options_dict()

    local_internal_options[AGENTD_INTERVAL] = test_metadata["interval"]

    configuration.set_local_internal_options_dict(local_internal_options)

    yield

    configuration.set_local_internal_options_dict(backup_local_internal_options)

