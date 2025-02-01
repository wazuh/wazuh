import json
import random
from unittest import mock

import httpx
import pytest
from wazuh.core.cluster.hap_helper.proxy import (
    CommunicationProtocol,
    Proxy,
    ProxyAPI,
    ProxyAPIMethod,
    ProxyBalanceAlgorithm,
    ProxyServerState,
    DEFAULT_TIMEOUT,
)
from wazuh.core.exception import WazuhHAPHelperError


class TestProxyAPI:
    METHODS_KWARGS = (
        'method,f_kwargs',
        [
            ('update_configuration_version', {}),
            ('get_runtime_info', {}),
            ('get_global_configuration', {}),
            ('update_global_configuration', {'new_configuration': {'foo': 1}}),
            ('get_backends', {}),
            ('add_backend', {'name': 'foo'}),
            ('get_backend_servers', {'backend': 'foo'}),
            (
                'add_server_to_backend',
                {'backend': 'foo', 'server_name': 'bar', 'server_address': '192.168.0.1', 'port': 1514},
            ),
            ('remove_server_from_backend', {'backend': 'foo', 'server_name': 'bar'}),
            ('get_frontends', {}),
            ('add_frontend', {'backend': 'foo', 'name': 'bar', 'port': 1514}),
            ('get_backend_server_runtime_settings', {'backend_name': 'foo', 'server_name': 'bar'}),
            (
                'change_backend_server_state',
                {'backend_name': 'foo', 'server_name': 'bar', 'state': ProxyServerState.DRAIN},
            ),
            ('get_backend_stats', {'backend_name': 'foo'}),
            ('get_backend_server_stats', {'backend_name': 'foo', 'server_name': 'bar'}),
        ],
    )

    @pytest.fixture
    def proxy_api(self):
        return ProxyAPI(username='test', password='test', tag='test')

    @pytest.fixture
    def get_mock(self):
        with mock.patch('framework.wazuh.core.cluster.hap_helper.proxy.httpx.AsyncClient.get') as get_mock:
            yield get_mock

    @pytest.fixture
    def request_mock(self):
        with mock.patch('framework.wazuh.core.cluster.hap_helper.proxy.httpx.AsyncClient.request') as request_mock:
            yield request_mock

    async def test_initialize(self, proxy_api: ProxyAPI, get_mock: mock.AsyncMock):
        """Check the correct function of `initialize` method."""

        await proxy_api.initialize()

        get_mock.assert_called_once_with(
            f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/health',
            auth=(proxy_api.username, proxy_api.password),
        )

    async def test_initialize_timeout(self, proxy_api: mock.MagicMock):
        """Check that the `initialize` method calls httpx.AsyncClient with a timeout."""

        with mock.patch('httpx.AsyncClient') as client:
            await proxy_api.initialize()

            client.assert_called_with(verify=mock.ANY, cert=mock.ANY, timeout=httpx.Timeout(DEFAULT_TIMEOUT))

    @pytest.mark.parametrize(
        'status_code,side_effect,expected',
        (
            [401, None, 3046],
            [404, None, 3047],
            [None, httpx.ConnectError, 3043],
            [None, httpx.RequestError, 3043],
        ),
    )
    async def test_initialize_ko(
        self,
        proxy_api: ProxyAPI,
        get_mock: mock.AsyncMock,
        status_code: int | None,
        side_effect: Exception | None,
        expected: int,
    ):
        """Check the correct error handling of `initialize` method."""

        if status_code is not None:
            get_mock.return_value = mock.MagicMock(status_code=status_code)

        if side_effect is not None:
            get_mock.side_effect = side_effect('Some error message')

        with pytest.raises(WazuhHAPHelperError, match=f'.*{expected}.*'):
            await proxy_api.initialize()

    @pytest.mark.parametrize(
        'response,side_effect,expected',
        (
            [{'status_code': 401, 'is_success': False}, None, 3046],
            [
                {
                    'status_code': random.choice([403, 404, 500]),
                    'is_success': False,
                    'json.return_value': {'message': 'error'},
                },
                None,
                3045,
            ],
            [{}, httpx.RequestError, 3044],
        ),
    )
    @pytest.mark.parametrize(*METHODS_KWARGS)
    async def test_proxy_method_ko(
        self,
        proxy_api: ProxyAPI,
        request_mock: mock.AsyncMock,
        response: dict,
        side_effect: Exception | None,
        expected: int,
        method,
        f_kwargs,
    ):
        """Check the correct error handling of all methods that call `_make_hap_request`."""

        if response:
            request_mock.return_value = mock.MagicMock(**response)
        if side_effect is not None:
            request_mock.side_effect = side_effect('Some error message')

        with pytest.raises(WazuhHAPHelperError, match=f'.*{expected}.*'):
            await getattr(proxy_api, method)(**f_kwargs)

    async def test_update_configuration_version(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check that `update_configuration_version` method sets the correct version."""

        endpoint = 'services/haproxy/configuration/version'
        version = '1'
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': version}
        )

        await proxy_api.update_configuration_version()

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )
        assert proxy_api.version == version

    async def test_get_runtime_info(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_runtime_info` method."""

        endpoint = 'services/haproxy/runtime/info'
        info = {'foo': 1, 'bar': 2}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': [{'info': info}]}
        )

        ret_val = await proxy_api.get_runtime_info()

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )
        assert ret_val == info

    async def test_get_global_configuration(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_global_configuration` method."""

        endpoint = 'services/haproxy/configuration/global'
        data = {'foo': 1, 'bar': 2}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': {'data': data}}
        )

        ret_val = await proxy_api.get_global_configuration()

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )
        assert ret_val == data

    async def test_update_global_configuration(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check that `update_globla_configuration` method makes the correct request."""

        endpoint = 'services/haproxy/configuration/global'
        version_endpoint = 'services/haproxy/configuration/version'
        new_configuration = {'foo': 1, 'bar': 2}
        request_mock.return_value = mock.MagicMock(
            **{
                'status_code': 202,
                'is_success': True,
                'json.side_effect': json.JSONDecodeError(msg='Some Error', doc='', pos=1),
            }
        )

        await proxy_api.update_global_configuration(new_configuration)

        assert request_mock.call_count == 2
        request_mock.assert_any_call(
            method=ProxyAPIMethod.PUT.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=new_configuration,
            params={'version': 0},
        )
        request_mock.assert_called_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{version_endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )

    async def test_get_backends(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_backends` method."""

        endpoint = 'services/haproxy/configuration/backends'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )

        ret_val = await proxy_api.get_backends()

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )
        assert ret_val == data

    async def test_add_backend(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check that `add_backend` method makes the correct request."""

        endpoint = 'services/haproxy/configuration/backends'
        version_endpoint = 'services/haproxy/configuration/version'

        request_mock.return_value = mock.MagicMock(**{'status_code': 200, 'is_success': True})

        name = 'foo'
        await proxy_api.add_backend(name)

        assert request_mock.call_count == 2
        request_mock.assert_any_call(
            method=ProxyAPIMethod.POST.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json={
                'name': name,
                'mode': CommunicationProtocol.TCP.value,
                'balance': {'algorithm': ProxyBalanceAlgorithm.LEAST_CONNECTIONS.value},
            },
            params={'force_reload': True, 'version': 0},
        )
        request_mock.assert_called_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{version_endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )

    async def test_get_backend_servers(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_backend_servers` method."""

        endpoint = 'services/haproxy/configuration/servers'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )

        backend = 'foo'
        ret_val = await proxy_api.get_backend_servers(backend)

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'backend': backend, 'version': 0},
        )
        assert ret_val == data

    @pytest.mark.parametrize(
        'server_address,is_ip_address,resolver',
        (['192.168.0.1', True, None], ['192.168.0.1', True, 'some-resolver'], ['some-address', False, 'some-resolver']),
    )
    async def test_add_server_to_backend(
        self,
        proxy_api: ProxyAPI,
        request_mock: mock.AsyncMock,
        server_address: str,
        is_ip_address: bool,
        resolver: str | None,
    ):
        """Check that `add_server_to_backend` method makes the correct request."""

        endpoint = 'services/haproxy/configuration/servers'
        version_endpoint = 'services/haproxy/configuration/version'

        request_mock.return_value = mock.MagicMock(**{'status_code': 201, 'is_success': True})

        backend = 'foo'
        server_name = 'bar'
        port = 1514

        json_body = {'check': 'enabled', 'name': server_name, 'address': server_address, 'port': port}

        json_body.update(
            {'resolvers': resolver, 'init-addr': 'last,libc,none'} if resolver is not None and not is_ip_address else {}
        )

        await proxy_api.add_server_to_backend(backend, server_name, server_address, port, resolver)

        assert request_mock.call_count == 2
        request_mock.assert_any_call(
            method=ProxyAPIMethod.POST.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=json_body,
            params={'backend': backend, 'force_reload': True, 'version': 0},
        )
        request_mock.assert_called_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{version_endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )

    async def test_remove_server_from_backend(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check that `remove_server_from_backend` method makes the correct request."""

        endpoint = 'services/haproxy/configuration/servers'
        version_endpoint = 'services/haproxy/configuration/version'

        request_mock.return_value = mock.MagicMock(**{'status_code': 204, 'is_success': True})

        backend = 'foo'
        server_name = 'bar'

        await proxy_api.remove_server_from_backend(backend, server_name)

        assert request_mock.call_count == 2
        request_mock.assert_any_call(
            method=ProxyAPIMethod.DELETE.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}/{server_name}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'backend': backend, 'force_reload': True, 'version': 0},
        )
        request_mock.assert_called_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{version_endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )

    async def test_get_frontends(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_frontends` method."""

        endpoint = 'services/haproxy/configuration/frontends'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )

        ret_val = await proxy_api.get_frontends()

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0},
        )
        assert ret_val == data

    async def test_add_frontend(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check that `add_frontend` method makes the correct request."""

        endpoint = 'services/haproxy/configuration/frontends'
        bind_endpoint = 'services/haproxy/configuration/binds'
        name = 'bar'

        request_mock.side_effect = (
            mock.MagicMock(**{'status_code': 201, 'is_success': True, 'json.return_value': {'name': name}}),
            mock.MagicMock(**{'status_code': 201, 'is_success': True, 'json.return_value': 1}),
            mock.MagicMock(**{'status_code': 201, 'is_success': True, 'json.return_value': {'foo': 'baz'}}),
            mock.MagicMock(**{'status_code': 201, 'is_success': True, 'json.return_value': 2}),
        )

        port = 1514
        backend = 'foo'

        await proxy_api.add_frontend(name, port, backend)

        assert request_mock.call_count == 4

        request_mock.assert_any_call(
            method=ProxyAPIMethod.POST.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json={'name': name, 'mode': CommunicationProtocol.TCP.value, 'default_backend': backend},
            params={'force_reload': True, 'version': 0},
        )
        request_mock.assert_any_call(
            method=ProxyAPIMethod.POST.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{bind_endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json={'port': port, 'name': f'{name}_bind'},
            params={'force_reload': True, 'frontend': name, 'version': 1},
        )

    async def test_get_backend_server_runtime_settings(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_backend_server_runtime_settings` method."""

        endpoint = 'services/haproxy/runtime/servers'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )

        backend_name = 'foo'
        server_name = 'bar'
        ret_val = await proxy_api.get_backend_server_runtime_settings(backend_name, server_name)

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}/{server_name}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'backend': backend_name, 'name': server_name, 'version': 0},
        )
        assert ret_val == data

    @pytest.mark.parametrize(
        'state',
        [
            ProxyServerState.DOWN,
            ProxyServerState.DRAIN,
            ProxyServerState.MAINTENANCE,
            ProxyServerState.READY,
            ProxyServerState.UP,
        ],
    )
    async def test_change_backend_server_state(
        self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock, state: ProxyServerState
    ):
        """Check that `change_backend_server_state` method makes the correct request."""

        endpoint = 'services/haproxy/runtime/servers'

        request_mock.return_value = mock.MagicMock(**{'status_code': 200, 'is_success': True})

        backend_name = 'foo'
        server_name = 'bar'

        await proxy_api.change_backend_server_state(backend_name, server_name, state)

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.PUT.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}/{server_name}',
            auth=(proxy_api.username, proxy_api.password),
            json={'admin_state': state.value},
            params={'backend': backend_name, 'version': 0},
        )

    async def test_get_backend_stats(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_backend_stats` method."""

        endpoint = 'services/haproxy/stats/native'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )

        backend_name = 'foo'
        ret_val = await proxy_api.get_backend_stats(backend_name)

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'type': 'backend', 'name': backend_name, 'version': 0},
        )
        assert ret_val == data

    async def test_get_backend_server_stats(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_backend_server_stats` method."""

        endpoint = 'services/haproxy/stats/native'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )

        backend_name = 'foo'
        server_name = 'bar'
        ret_val = await proxy_api.get_backend_server_stats(backend_name, server_name)

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'type': 'server', 'parent': backend_name, 'name': server_name, 'version': 0},
        )
        assert ret_val == data

    async def test_get_binds(self, proxy_api: ProxyAPI, request_mock: mock.AsyncMock):
        """Check the correct output of `get_binds` method."""

        endpoint = 'services/haproxy/configuration/binds'
        data = {'data': {'foo': 1, 'bar': 2}}
        request_mock.return_value = mock.MagicMock(
            **{'status_code': 200, 'is_success': True, 'json.return_value': data}
        )
        frontend = 'baz'

        ret_val = await proxy_api.get_binds(frontend=frontend)

        request_mock.assert_called_once_with(
            method=ProxyAPIMethod.GET.value,
            url=f'{proxy_api.protocol}://{proxy_api.address}:{proxy_api.port}/v2/{endpoint}',
            auth=(proxy_api.username, proxy_api.password),
            json=None,
            params={'version': 0, 'frontend': frontend},
        )
        assert ret_val == data


class TestProxy:
    @pytest.fixture
    def proxy_api_mock(self):
        with mock.patch('framework.wazuh.core.cluster.hap_helper.proxy.ProxyAPI', autospec=True) as proxy_api_mock:
            yield proxy_api_mock

    @pytest.fixture
    def proxy(self, proxy_api_mock: mock.MagicMock):
        proxy = Proxy(wazuh_backend='test', proxy_api=proxy_api_mock, tag='test')
        with mock.patch.object(proxy, 'logger'):
            yield proxy

    @pytest.mark.parametrize('hard_stop_after,expected', ([3000, 3], [None, None]))
    async def test_initialize(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, hard_stop_after: int | None, expected: int | None
    ):
        """Check the correct function of `initialize` method."""

        proxy_api_mock.get_runtime_info.return_value = {'version': 1}

        with mock.patch.object(
            proxy, 'get_hard_stop_after_value', return_value=hard_stop_after
        ) as hard_stop_after_mock:
            await proxy.initialize()
            hard_stop_after_mock.assert_called_once()
        proxy_api_mock.initialize.assert_called_once()
        proxy_api_mock.get_runtime_info.assert_called_once()
        assert proxy.hard_stop_after == expected

    @pytest.mark.parametrize('side_effect', [KeyError, IndexError])
    async def test_initialize_ko(self, proxy_api_mock: mock.MagicMock, proxy: Proxy, side_effect: Exception):
        """Check the correct error handling of `initialize` method."""

        proxy_api_mock.get_runtime_info.side_effect = side_effect
        with pytest.raises(WazuhHAPHelperError, match='.*3048.*'):
            await proxy.initialize()

    @pytest.mark.parametrize(
        'global_configuration,expected', ([{'hard_stop_after': 3000}, 3000], [{'foo': 'bar'}, None])
    )
    async def test_get_hard_stop_after_value(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, global_configuration: int, expected: int | None
    ):
        """Check the correct output of `get_hard_stop_after` method."""

        proxy_api_mock.get_global_configuration.return_value = global_configuration

        assert (await proxy.get_hard_stop_after_value()) == expected
        proxy_api_mock.get_global_configuration.assert_called_once()

    @pytest.mark.parametrize(
        'hard_stop_after,new_configuration',
        ([None, {'hard_stop_after': 70000}], [50.0, {'hard_stop_after': 70000}], [70.0, {}]),
    )
    async def test_set_hard_stop_after_value(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, hard_stop_after: float | None, new_configuration: dict
    ):
        """Check the correct function of `set_hard_stop_after` method."""

        proxy_api_mock.get_global_configuration.return_value = {}
        proxy.hard_stop_after = hard_stop_after
        await proxy.set_hard_stop_after_value(
            active_agents=20, n_managers=3, chunk_size=5, agent_reconnection_time=10, server_admin_state_delay=5
        )

        if new_configuration:
            proxy_api_mock.update_global_configuration.assert_called_once_with(new_configuration=new_configuration)
        else:
            proxy_api_mock.update_global_configuration.assert_not_called()

    async def test_get_current_pid(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_current_pid` method."""

        pid = 10
        proxy_api_mock.get_runtime_info.return_value = {'pid': pid}

        assert (await proxy.get_current_pid()) == pid

    async def test_get_current_backends(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_current_backends` method."""

        backends = [
            {'name': 'backend1', 'mode': 'http', 'adv_check': 'httpchk', 'balance': {'algorithm': 'roundrobin'}},
            {'name': 'backend2', 'mode': 'http', 'adv_check': 'httpchk', 'balance': {'algorithm': 'roundrobin'}},
        ]
        proxy_api_mock.get_backends.return_value = {'data': backends}

        ret_val = await proxy.get_current_backends()

        proxy_api_mock.get_backends.assert_called_once()
        assert ret_val == {backend['name']: backend for backend in backends}

    @pytest.mark.parametrize(
        'current_backends,backend,expected', ([{'backend1': {}}, 'backend1', True], [{}, 'backend1', False])
    )
    async def test_exists_backend(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, current_backends: dict, backend: str, expected: bool
    ):
        """Check the correct output of `exists_backend` method."""

        with mock.patch.object(proxy, 'get_current_backends', return_value=current_backends):
            assert await proxy.exists_backend(backend) == expected

    async def test_get_current_frontends(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_current_frontends` method."""

        frontends = [
            {'name': 'frontend1', 'mode': 'http', 'default_backend': 'backend1'},
            {'name': 'frontend2', 'mode': 'http'},
        ]
        proxy_api_mock.get_frontends.return_value = {'data': frontends}

        ret_val = await proxy.get_current_frontends()

        proxy_api_mock.get_frontends.assert_called_once()
        assert ret_val == {frontend['name']: frontend for frontend in frontends if 'default_backend' in frontend}

    @pytest.mark.parametrize(
        'current_frontends,frontend,expected', ([{'frontend1': {}}, 'frontend1', True], [{}, 'frontend1', False])
    )
    async def test_exists_frontend(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, current_frontends: dict, frontend: str, expected: bool
    ):
        """Check the correct output of `exists_frontend` method."""

        with mock.patch.object(proxy, 'get_current_frontends', return_value=current_frontends):
            assert await proxy.exists_frontend(frontend) == expected

    @pytest.mark.parametrize(
        'binds,expected',
        (
            [
                ({'data': [{'name': 'bar_bind', 'port': '1514'}]}, {'data': [{'name': 'baz_bind'}]}),
                True,
            ],
            [
                ({'data': [{'name': 'bar_bind', 'port': '2000'}]}, {'data': [{'name': 'baz_bind'}]}),
                False,
            ],
            [
                ({'data': [{'name': 'bar_bind', 'port': '2000'}]}, {'data': [{'name': 'baz_bind', 'port': '1516'}]}),
                False,
            ],
            [
                ({'data': [{'name': 'bar_bind'}]}, {'data': [{'name': 'baz_bind', 'port': '1514'}]}),
                True,
            ],
        ),
    )
    async def test_check_multiple_frontends(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, binds: tuple, expected: bool
    ):
        """Check the correct output of `check_multiple_frontends` method."""
        FRONTEND1 = 'foo'
        current_frontends = {FRONTEND1: {}, 'bar': {}, 'baz': {}}
        proxy_api_mock.get_binds.side_effect = binds

        with mock.patch.object(proxy, 'get_current_frontends', return_value=current_frontends):
            assert await proxy.check_multiple_frontends('1514', frontend_to_skip=FRONTEND1) == expected

    async def test_add_new_backend(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check that `add_new_backend` method makes the correct callback."""

        parameters = {
            'name': 'foo',
            'mode': CommunicationProtocol.TCP,
            'algorithm': ProxyBalanceAlgorithm.LEAST_CONNECTIONS,
        }

        await proxy.add_new_backend(**parameters)

        proxy_api_mock.add_backend.assert_called_once_with(**parameters)

    async def test_add_new_frontend(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check that `add_new_frontend` method makes the correct callback."""

        parameters = {'name': 'foo', 'port': 1514, 'backend': 'bar', 'mode': CommunicationProtocol.TCP}

        await proxy.add_new_frontend(**parameters)

        proxy_api_mock.add_frontend.assert_called_once_with(**parameters)

    async def test_get_current_backend_servers(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_current_backend_servers` method."""

        servers = [
            {'name': 'server1', 'address': '192.168.0.1'},
            {'name': 'server2', 'address': '192.168.0.2'},
        ]
        proxy_api_mock.get_backend_servers.return_value = {'data': servers}

        ret_val = await proxy.get_current_backend_servers()

        proxy_api_mock.get_backend_servers.assert_called_once_with(backend=proxy.wazuh_backend)
        assert ret_val == {server['name']: server['address'] for server in servers}

    async def test_add_wazuh_manager(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check that `add_wazuh_manager` method makes the correct callback."""

        manager_name = 'foo'
        manager_address = '192.168.0.1'
        resolver = 'test-resolver'

        await proxy.add_wazuh_manager(manager_name, manager_address, resolver)

        proxy_api_mock.add_server_to_backend.assert_called_once_with(
            backend=proxy.wazuh_backend,
            server_name=manager_name,
            server_address=manager_address,
            port=proxy.wazuh_connection_port,
            resolver=resolver,
        )

    async def test_remove_wazuh_manager(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check that `remove_wazuh_manager` method makes the correct callback."""

        manager_name = 'foo'

        await proxy.remove_wazuh_manager(manager_name)

        proxy_api_mock.remove_server_from_backend.assert_called_with(
            backend=proxy.wazuh_backend, server_name=manager_name
        )

    async def test_restrain_server_new_connections(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check that `restrain_server_new_connections` method makes the correct callback."""

        server_name = 'foo'

        await proxy.restrain_server_new_connections(server_name)

        proxy_api_mock.change_backend_server_state.assert_called_once_with(
            backend_name=proxy.wazuh_backend, server_name=server_name, state=ProxyServerState.DRAIN
        )

    async def test_allow_server_new_connections(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check that `allow_server_new_connections` method makes the correct callback."""

        server_name = 'foo'

        await proxy.allow_server_new_connections(server_name)

        proxy_api_mock.change_backend_server_state.assert_called_once_with(
            backend_name=proxy.wazuh_backend, server_name=server_name, state=ProxyServerState.READY
        )

    async def test_get_wazuh_server_stats(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_wazuh_server_stats` method."""

        stats = {'foo': 'bar'}
        proxy_api_mock.get_backend_server_stats.return_value = [{'stats': [{'stats': stats}]}]
        server_name = 'foo'
        assert (await proxy.get_wazuh_server_stats(server_name)) == stats
        proxy_api_mock.get_backend_server_stats.assert_called_once_with(
            backend_name=proxy.wazuh_backend, server_name=server_name
        )

    @pytest.mark.parametrize(
        'state,expected',
        (
            [ProxyServerState.DRAIN.value, True],
            [random.choice([ProxyServerState.READY.value, ProxyServerState.MAINTENANCE.value]), False],
        ),
    )
    async def test_is_server_drain(
        self, proxy_api_mock: mock.MagicMock, proxy: Proxy, state: ProxyServerState, expected: bool
    ):
        """Check the correct output of `is_server_drain` method."""

        proxy_api_mock.get_backend_server_runtime_settings.return_value = {'admin_state': state}

        server_name = 'foo'
        assert (await proxy.is_server_drain(server_name)) == expected
        proxy_api_mock.get_backend_server_runtime_settings.assert_called_once_with(
            backend_name=proxy.wazuh_backend, server_name=server_name
        )

    async def test_get_wazuh_backend_stats(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_wazuh_backend_stats` method."""

        servers = [
            {'name': 'server1', 'address': '192.168.0.1'},
            {'name': 'server2', 'address': '192.168.0.2'},
        ]
        proxy_api_mock.get_backend_servers.return_value = {'data': servers}

        with mock.patch.object(
            proxy, 'get_wazuh_server_stats', return_value={'status': ProxyServerState.UP.value.upper()}
        ) as server_stats_mock:
            stats = await proxy.get_wazuh_backend_stats()
            assert len(stats.keys()) == len(servers)
            server_stats_mock.call_count = len(servers)
            for server in servers:
                server_stats_mock.assert_any_call(server_name=server['name'])

    async def test_get_wazuh_backend_server_connections(self, proxy_api_mock: mock.MagicMock, proxy: Proxy):
        """Check the correct output of `get_wazuh_backend_server_connections` method."""

        stats = {
            'server1': {'scur': 10},
            'server2': {'scur': 20},
        }
        with mock.patch.object(proxy, 'get_wazuh_backend_stats', return_value=stats) as backend_stats_mock:
            ret_stats = await proxy.get_wazuh_backend_server_connections()
            backend_stats_mock.assert_called_once()
            assert ret_stats == {'server1': 10, 'server2': 20}
