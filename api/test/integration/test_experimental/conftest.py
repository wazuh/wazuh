import pytest
import time
import os

@pytest.fixture(name="experimental_test", scope="session")
def fix_test():
    os.system("docker-compose -p ./environment_experimental/docker-compose.yml up --build -d")
    time.sleep(60)
    print('Environment ready, starting tests')
    yield
    print('Tests finished')
    os.system("docker-compose down")
