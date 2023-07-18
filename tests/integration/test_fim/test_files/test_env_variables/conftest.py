

import os
import subprocess
import sys

import pytest

from wazuh_testing.constants.platforms import WINDOWS


@pytest.fixture(scope='module')
def set_environment_variables(test_metadata: dict) -> None:
    """
    Create environment variables
    """
    environment_variables = test_metadata.get('environment_variables')
    for env, value in environment_variables:
        if sys.platform == WINDOWS:
            subprocess.call(['setx.exe', env, value, '/m'])
        else:
            os.putenv(env, value)

    yield

    for env in environment_variables:
        os.environ.pop[env]
