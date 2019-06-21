import pytest
import time
import os


@pytest.fixture(name="agents_test", scope="session")
def fix_test():
    os.system("docker-compose up --build -d")
    time.sleep(60)
    print('Entorno configurado - Comienzan los test')
    yield
    print('Test finalizados')
    os.system("docker-compose down")


@pytest.fixture(name="ciscat_tests", scope="session")
def fix_test():
    print('Preparing environment')
    os.system("docker-compose -f ciscat/docker-compose.yml up --build -d --scale wazuh-agent-ciscat=10")
    time.sleep(120)
    print('Environment configured, starting tests')
    yield
    print('Finalized tests')
    os.system("docker-compose down")
