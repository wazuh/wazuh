# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body


class APIConfigurationModel(Body):
    """API configuration model."""
    def __init__(self, host=None, port=None, behind_proxy_server=None, https=None, logs=None, cors=None,
                 cache=None, use_only_authd=None, drop_privileges=None, experimental_features=None):
        self.swagger_types = {
            'host': str,
            'port': int,
            'behind_proxy_server': bool,
            'https': dict,
            'logs': dict,
            'cors': dict,
            'cache': dict,
            'use_only_authd': bool,
            'drop_privileges': bool,
            'experimental_features': bool
        }

        self.attribute_map = {
            'host': 'host',
            'port': 'port',
            'behind_proxy_server': 'behind_proxy_server',
            'https': 'https',
            'logs': 'logs',
            'cors': 'cors',
            'cache': 'cache',
            'use_only_authd': 'use_only_authd',
            'drop_privileges': 'drop_privileges',
            'experimental_features': 'experimental_features'
        }

        self._host = host
        self._port = port
        self._behind_proxy_server = behind_proxy_server
        self._https = https
        self._logs = logs
        self._cors = cors
        self._cache = cache
        self._use_only_authd = use_only_authd
        self._drop_privileges = drop_privileges
        self._experimental_features = experimental_features

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        self._host = host

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, port):
        self._port = port

    @property
    def behind_proxy_server(self):
        return self._behind_proxy_server

    @behind_proxy_server.setter
    def behind_proxy_server(self, behind_proxy_server):
        self._behind_proxy_server = behind_proxy_server

    @property
    def https(self):
        return self._https

    @https.setter
    def https(self, https):
        self._https = https

    @property
    def logs(self):
        return self._logs

    @logs.setter
    def logs(self, logs):
        self._logs = logs

    @property
    def cors(self):
        return self._cors

    @cors.setter
    def cors(self, cors):
        self._cors = cors

    @property
    def cache(self):
        return self._cache

    @cache.setter
    def cache(self, cache):
        self._cache = cache

    @property
    def use_only_authd(self):
        return self._use_only_authd

    @use_only_authd.setter
    def use_only_authd(self, use_only_authd):
        self._use_only_authd = use_only_authd

    @property
    def drop_privileges(self):
        return self._drop_privileges

    @drop_privileges.setter
    def drop_privileges(self, drop_privileges):
        self._drop_privileges = drop_privileges

    @property
    def experimental_features(self):
        return self._experimental_features

    @experimental_features.setter
    def experimental_features(self, experimental_features):
        self._experimental_features = experimental_features


class SecurityConfigurationModel(Body):
    """Security configuration model."""

    def __init__(self, auth_token_exp_timeout: int = None, rbac_mode: str = None):
        self.swagger_types = {
            'auth_token_exp_timeout': int,
            'rbac_mode': str,
        }

        self.attribute_map = {
            'auth_token_exp_timeout': 'auth_token_exp_timeout',
            'rbac_mode': 'rbac_mode'
        }

        self._auth_token_exp_timeout = auth_token_exp_timeout
        self._rbac_mode = rbac_mode

    @property
    def auth_token_exp_timeout(self):
        return self._auth_token_exp_timeout

    @auth_token_exp_timeout.setter
    def auth_token_exp_timeout(self, auth_token_exp_timeout):
        self._auth_token_exp_timeout = auth_token_exp_timeout

    @property
    def rbac_mode(self):
        return self._rbac_mode

    @rbac_mode.setter
    def rbac_mode(self, rbac_mode):
        self._rbac_mode = rbac_mode
