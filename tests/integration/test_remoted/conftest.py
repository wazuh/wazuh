import pytest

from wazuh_testing.utils import services
from wazuh_testing.utils.services import check_all_daemon_status


@pytest.fixture
def restart_wazuh_expect_error() -> None:
    try:
        if any(v == True for _, v in check_all_daemon_status().items()) :
           services.control_service('restart')
        else:
            services.control_service('start')
    except:
        pass

    yield

    services.control_service('stop')


'''
    description: elements from section config and convert  list to dict
    return  real config list
'''
@pytest.fixture
def get_real_configuration(test_configuration):
    config_data = test_configuration.get('sections', {})[0]['elements']
    real_config = dict()

    for I in config_data:
        for key in I:
            real_config[key] = I[key]

    if real_config.get('protocol'):
        real_config['protocol']['value'] = real_config['protocol']['value'].split(',')

    real_config_list = list()
    real_config_list.append(real_config)
    return real_config_list
