

import os
import subprocess
import sys

import pytest

from wazuh_testing.constants.platforms import WINDOWS


@pytest.fixture()
def set_environment_variables(test_metadata: dict) -> None:
    """
    Create environment variables
    """
    environment_variables: dict = test_metadata.get('environment_variables')
    print(environment_variables)
    for env, value in environment_variables.items():
        if sys.platform == WINDOWS:
            subprocess.call(['setx.exe', env, value, '/m'])
        else:
            # subprocess.run(f"export {env}='{value}'", shell=True)
            os.environ[env] = value

    yield

    for env in environment_variables.keys():
        os.environ.pop(env)
