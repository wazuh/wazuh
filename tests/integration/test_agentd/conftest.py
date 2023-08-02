# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.constants.paths.variables import AGENTD_STATE 
from wazuh_testing.modules.agentd.configuration import AGENTD_INTERVAL

@pytest.fixture()
def remove_state_file() -> None:
    # Remove state file to check if agent behavior is as expected
    os.remove(AGENTD_STATE) if os.path.exists(AGENTD_STATE) else None

@pytest.fixture()
def set_state_interval() -> None:
    import pdb; pdb.set_trace()
    local_internal_options[AGENTD_INTERVAL] = test_configuration['interval']
