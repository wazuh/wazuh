

import os
import subprocess
import sys

import pytest

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.utils import file


@pytest.fixture(scope='module')
def set_environment_variables() -> None:
    """
    Create environment variables
    """
    # environment_variables: dict = test_metadata.get('environment_variables')
    file.create_folder('/test_dir1')
    environment_variables: dict = {'TESTING': '/test_dir1'}
    print(environment_variables)
    for env, value in environment_variables.items():
        if sys.platform == WINDOWS:
            subprocess.call(['setx.exe', env, value, '/m'])
        else:
            print(f"export {env}={value}")
            subprocess.call(f'export {env}=/test_dir1/', shell=True)
            os.environ[env] = value
            os.putenv(env, value)

    yield

    for env in environment_variables.keys():
        os.environ.pop(env)
