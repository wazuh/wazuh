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