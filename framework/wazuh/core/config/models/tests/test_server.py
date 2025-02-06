from unittest.mock import patch

import pytest
from pydantic import ValidationError
from wazuh.core.config.models.server import (
    DEFAULT_CTI_URL,
    CommunicationsConfig,
    CommunicationsTimeoutConfig,
    CTIConfig,
    JWTConfig,
    MasterConfig,
    MasterIntervalsConfig,
    MasterProcesses,
    NodeConfig,
    ServerConfig,
    ServerSyncConfig,
    SharedFiles,
    WorkerConfig,
    WorkerIntervalsConfig,
    WorkerRetriesConfig,
    ZipConfig,
)


@pytest.mark.parametrize('init_values, expected', [
    (
            {},
            {
                'timeout_extra_valid': 40,
                'recalculate_integrity': 8,
                'check_worker_last_keep_alive': 60,
                'max_allowed_time_without_keep_alive': 120,
                'max_locked_integrity_time': 1000
            }
    ),
    (
            {
                'timeout_extra_valid': 10,
                'recalculate_integrity': 4,
                'check_worker_last_keep_alive': 20,
                'max_allowed_time_without_keep_alive': 60,
                'max_locked_integrity_time': 500
            },
            {
                'timeout_extra_valid': 10,
                'recalculate_integrity': 4,
                'check_worker_last_keep_alive': 20,
                'max_allowed_time_without_keep_alive': 60,
                'max_locked_integrity_time': 500
            }
    )
])
def test_master_intervals_config_default_values(init_values, expected):
    """Check the correct initialization of the `MasterIntervalsConfig` class."""
    config = MasterIntervalsConfig(**init_values)

    assert config.timeout_extra_valid == expected['timeout_extra_valid']
    assert config.recalculate_integrity == expected['recalculate_integrity']
    assert config.check_worker_last_keep_alive == expected['check_worker_last_keep_alive']
    assert config.max_allowed_time_without_keep_alive == expected['max_allowed_time_without_keep_alive']
    assert config.max_locked_integrity_time == expected['max_locked_integrity_time']


@pytest.mark.parametrize('values', [
    {'timeout_extra_valid': 0},
    {'timeout_extra_valid': -20},
    {'recalculate_integrity': 0},
    {'recalculate_integrity': -100},
    {'check_worker_last_keep_alive': 0},
    {'check_worker_last_keep_alive': -24},
    {'max_allowed_time_without_keep_alive': 0},
    {'max_allowed_time_without_keep_alive': -21},
    {'max_locked_integrity_time': 0},
    {'max_locked_integrity_time': -40}

])
def test_master_intervals_config_invalid_values(values):
    """Check the correct behavior of the `MasterIntervalsConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = MasterIntervalsConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'process_pool_size': 2}),
    ({'process_pool_size': 4}, {'process_pool_size': 4})
])
def test_master_processes_default_values(init_values, expected):
    """Check the correct initialization of the `MasterProcesses` class."""
    config = MasterProcesses(**init_values)

    assert config.process_pool_size == expected['process_pool_size']


@pytest.mark.parametrize('values', [
    {'process_pool_size': 0},
    {'process_pool_size': -4}
])
def test_master_processes_invalid_values(values):
    """Check the correct behavior of the `MasterProcesses` class validations."""
    with pytest.raises(ValidationError):
        _ = MasterProcesses(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'intervals': {}, 'processes': {}}),
    ({'intervals': {'timeout_extra_valid': 80}, 'processes': {'process_pool_size': 6}},
     {'intervals': {'timeout_extra_valid': 80}, 'processes': {'process_pool_size': 6}})
])
def test_master_config_default_values(init_values, expected):
    """Check the correct initialization of the `MasterConfig` class."""
    config = MasterConfig(**init_values)

    assert config.intervals == MasterIntervalsConfig(**expected['intervals'])
    assert config.processes == MasterProcesses(**expected['processes'])


@pytest.mark.parametrize('values', [
    {'name': '', 'type': 'master', 'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}},
    {'name': 'example', 'type': 'invalid', 'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}},
    {'name': 'example', 'type': 'master'}
])
def test_node_config_invalid_values(values):
    """Check the correct behavior of the `NodeConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = NodeConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'max_size': 1073741824, 'min_size': 31457280, 'compress_level': 1, 'limit_tolerance': 0.2}),
    ({'max_size': 106, 'min_size': 100, 'compress_level': 6, 'limit_tolerance': 0.7},
     {'max_size': 106, 'min_size': 100, 'compress_level': 6, 'limit_tolerance': 0.7})
])
def test_zip_config_default_values(init_values, expected):
    """Check the correct initialization of the `ZipConfig` class."""
    config = ZipConfig(**init_values)

    assert config.max_size == expected['max_size']
    assert config.min_size == expected['min_size']
    assert config.compress_level == expected['compress_level']
    assert config.limit_tolerance == expected['limit_tolerance']


@pytest.mark.parametrize('values', [
    {'max_size': 0},
    {'max_size': -20},
    {'min_size': 0},
    {'min_size': -30},
    {'compress_level': -1},
    {'compress_level': 10},
    {'limit_tolerance': -0.1},
    {'limit_tolerance': 1.1}
])
def test_zip_config_invalid_values(values):
    """Check the correct behavior of the `ZipConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = ZipConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'dapi_request': 200, 'cluster_request': 20, 'receiving_file': 120}),
    ({'dapi_request': 100, 'cluster_request': 30, 'receiving_file': 20},
     {'dapi_request': 100, 'cluster_request': 30, 'receiving_file': 20})
])
def test_communications_timeout_config_default_values(init_values, expected):
    """Check the correct initialization of the `CommunicationsTimeoutConfig` class."""
    config = CommunicationsTimeoutConfig(**init_values)

    assert config.dapi_request == expected['dapi_request']
    assert config.cluster_request == expected['cluster_request']
    assert config.receiving_file == expected['receiving_file']


@pytest.mark.parametrize('values', [
    {'dapi_request': 0},
    {'dapi_request': -20},
    {'cluster_request': 0},
    {'cluster_request': -30},
    {'receiving_file': 0},
    {'receiving_file': -30}
])
def test_communications_timeout_config_invalid_values(values):
    """Check the correct behavior of the `CommunicationsTimeoutConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = CommunicationsTimeoutConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'zip': {}, 'timeouts': {}}),
    ({'zip': {'max_size': 40}, 'timeouts': {'dapi_request': 100}},
     {'zip': {'max_size': 40}, 'timeouts': {'dapi_request': 100}})
])
def test_communications_config_default_values(init_values, expected):
    """Check the correct initialization of the `CommunicationsConfig` class."""
    config = CommunicationsConfig(**init_values)

    assert config.zip == ZipConfig(**expected['zip'])
    assert config.timeouts == CommunicationsTimeoutConfig(**expected['timeouts'])


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'sync_integrity': 9, 'keep_alive': 60, 'connection_retry': 10}),
    ({'sync_integrity': 4, 'keep_alive': 30, 'connection_retry': 20},
     {'sync_integrity': 4, 'keep_alive': 30, 'connection_retry': 20})
])
def test_workers_intervals_config_default_values(init_values, expected):
    """Check the correct initialization of the `WorkerIntervalsConfig` class."""
    config = WorkerIntervalsConfig(**init_values)

    assert config.sync_integrity == expected['sync_integrity']
    assert config.keep_alive == expected['keep_alive']
    assert config.connection_retry == expected['connection_retry']


@pytest.mark.parametrize('values', [
    {'sync_integrity': 0},
    {'sync_integrity': -9},
    {'keep_alive': 0},
    {'keep_alive': -40},
    {'connection_retry': 0},
    {'connection_retry': -10}
])
def test_worker_intervals_config_invalid_values(values):
    """Check the correct behavior of the `WorkerIntervalsConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = WorkerIntervalsConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'max_failed_keepalive_attempts': 2}),
    ({'max_failed_keepalive_attempts': 10}, {'max_failed_keepalive_attempts': 10})
])
def test_worker_retries_config_default_values(init_values, expected):
    """Check the correct initialization of the `WorkerRetriesConfig` class."""
    config = WorkerRetriesConfig(**init_values)

    assert config.max_failed_keepalive_attempts == expected['max_failed_keepalive_attempts']


@pytest.mark.parametrize('values', [
    {'max_failed_keepalive_attempts': 0},
    {'max_failed_keepalive_attempts': -2},
])
def test_worker_retries_config_invalid_values(values):
    """Check the correct behavior of the `WorkerRetriesConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = WorkerRetriesConfig(**values)


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'intervals': {}, 'retries': {}}),
    ({'intervals': {'connection_retry': 20}, 'retries': {'max_failed_keepalive_attempts': 3}},
     {'intervals': {'connection_retry': 20}, 'retries': {'max_failed_keepalive_attempts': 3}})
])
def test_worker_config_default_values(init_values, expected):
    """Check the correct initialization of the `WorkerConfig` class."""
    config = WorkerConfig(**init_values)

    assert config.intervals == WorkerIntervalsConfig(**expected['intervals'])
    assert config.retries == WorkerRetriesConfig(**expected['retries'])


@pytest.mark.parametrize('values', [
    {'permissions': 0},
    {'permissions': -2},
])
def test_shared_files_invalid_values(values):
    """Check the correct behavior of the `SharedFiles` class validations."""
    with pytest.raises(ValidationError):
        _ = SharedFiles(**values)


@pytest.mark.parametrize('test_list, name, expected', [
    (
        [
            SharedFiles(dir='example1', description='', permissions=2, source='', names=['example'],
                        recursive=True, restart=True, remove_subdirs_if_empty=False, extra_valid=False),
            SharedFiles(dir='example2', description='', permissions=2, source='', names=['example'],
                        recursive=True, restart=True, remove_subdirs_if_empty=False, extra_valid=False)
        ],
        'example1',
        SharedFiles(dir='example1', description='', permissions=2, source='', names=['example'],
                    recursive=True, restart=True, remove_subdirs_if_empty=False, extra_valid=False)
    ),
    (
        [], 'example1', None
    )
])
def test_server_sync_config_get_dir_config(test_list, name, expected):
    """Check the correct behavior of the `get_dir_config` method."""
    config = ServerSyncConfig(files=test_list, excluded_files=[], excluded_extensions=[])
    result = config.get_dir_config(name)

    assert result == expected


@pytest.mark.parametrize('init_values, expected', [
    ({}, {'update_check': True, 'url': DEFAULT_CTI_URL}),
    ({'update_check': False, 'url': 'www.wazuh.com'}, {'update_check': False, 'url': 'www.wazuh.com'})
])
def test_cti_config_default_values(init_values, expected):
    """Check the correct initialization of the `CTIConfig` class."""
    config = CTIConfig(**init_values)

    assert config.update_check == expected['update_check']
    assert config.url == expected['url']


@pytest.mark.parametrize('init_values', [
    {'private_key': 'private_key_example', 'public_key': 'public_key_example'}
])
@patch('os.path.isfile', return_value=True)
def test_jwt_config_default_values(file_exists_mock, init_values):
    """Check the correct initialization of the `JWTConfig` class."""
    jwt_config = JWTConfig(**init_values)

    assert jwt_config.private_key == init_values['private_key']
    assert jwt_config.public_key == init_values['public_key']


@pytest.mark.parametrize('init_values', [
    {},
    {'private_key': 'key_example'},
    {'public_key': 'key_example'},
])
def test_jwt_config_fails_without_values(init_values):
    """Check the correct behavior of the `JWTConfig` class validations."""
    with pytest.raises(ValidationError):
        JWTConfig(**init_values)


@pytest.mark.parametrize('init_values, expected', [
    ({'nodes': ['master'], 'node': {'name': 'example', 'type': 'master', 'ssl':
        {'key': 'value', 'cert': 'value', 'ca': 'value'}}, 'jwt': {'public_key': 'value', 'private_key': 'value'}},
     {'port': 1516, 'bind_addr': 'localhost', 'nodes': ['master'], 'hidden': False, 'update_check': False, 'node':
         {'name': 'example', 'type': 'master', 'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}}})
])
@patch('wazuh.core.config.models.base.ValidateFilePathMixin._validate_file_path')
def test_server_config_default_values(file_path_validation_mock, init_values, expected):
    """Check the correct initialization of the `ServerConfig` class."""
    config = ServerConfig(**init_values)

    assert config.port == expected['port']
    assert config.bind_addr == expected['bind_addr']
    assert config.nodes == expected['nodes']
    assert config.hidden == expected['hidden']
    assert config.update_check == expected['update_check']
    assert config.node == NodeConfig(**expected['node'])


@pytest.mark.parametrize('values', [
    {'port': 0},
    {'port': -20},
    {'nodes': []},
    {}
])
def test_server_config_invalid_values(values):
    """Check the correct behavior of the `ServerConfig` class validations."""
    node_dict = {'name': 'example', 'type': 'master', 'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}}
    with pytest.raises(ValidationError):
        _ = ServerConfig(node=node_dict, **values)
