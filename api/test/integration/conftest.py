import pytest
import time
import os

@pytest.fixture(name="agents_test", scope="session")
def fix_test():
    os.chdir("./agent_enviroment")
    os.system("docker-compose up --build -d")
    time.sleep(60)
    print('Entorno configurado - Comienzan los test')
    yield
    print('Test finalizados')
    os.system("docker-compose down")


@pytest.fixture(name="agent_tests", scope="session")
def fix_test():
    here = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(here, 'environment', 'agents', 'docker-compose.yml')
    os.system(f"docker-compose -f {test_path} up --build -d")
    time.sleep(90)
    yield
    os.system(f"docker-compose -f {test_path} down")