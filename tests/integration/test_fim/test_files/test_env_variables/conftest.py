

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
    file.create_folder('/test_dir')
    environment_variables: dict = {'TESTING': '/test_dir'}
    print(environment_variables)
    os.putenv('TEST', '/test_dir')
    # for env, value in environment_variables.items():
    #     if sys.platform == WINDOWS:
    #         subprocess.call(['setx.exe', env, value, '/m'])
    #     else:
    #         print(f"export {env}={value}")
    #         subprocess.call(f'export {env}=/test_dir/', shell=True)
    #         os.environ[env] = value
    #         os.putenv(env, value)
    #         subprocess.call(f'export TESTING=/test_dir', shell=True)
    #         subprocess.call(f'export TEST=/test_dir', shell=True)

    yield

    # for env in environment_variables.keys():
    #     os.environ.pop(env)
