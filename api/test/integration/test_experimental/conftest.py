import pytest
import time
import os

@pytest.fixture(name="experimental_test", scope="session")
def fix_test():
    os.system("docker-compose -f ./environment_experimental/docker-compose.yml up --build -d")
    time.sleep(20)
    print('Environment ready, starting tests')
    yield
    print('\nTests finished')
    os.system("docker-compose -f ./environment_experimental/docker-compose.yml down")
