# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body, Model


class HTTPSModel(Model):
    def __init__(self, enabled=None, key=None, cert=None, use_ca=None, ca=None):
        self.swagger_types = {
            'enabled': bool,
            'key': str,
            'cert': str,
            'use_ca': bool,
            'ca': str
        }

        self.attribute_map = {
            'enabled': 'enabled',
            'key': 'key',
            'cert': 'cert',
            'use_ca': 'use_ca',
            'ca': 'ca'
        }

        self._enabled = enabled
        self._key = key
        self._cert = cert
        self._use_ca = use_ca
        self._ca = ca

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        self._key = key

    @property
    def cert(self):
        return self._cert

    @cert.setter
    def cert(self, cert):
        self._cert = cert

    @property
    def use_ca(self):
        return self._use_ca

    @use_ca.setter
    def use_ca(self, use_ca):
        self._use_ca = use_ca

    @property
    def ca(self):
        return self._ca

    @ca.setter
    def ca(self, ca):
        self._ca = ca


class LogsModel(Model):
    def __init__(self, level=None):
        self.swagger_types = {
            'level': str,
        }

        self.attribute_map = {
            'level': 'level',
        }

        self._level = level

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, level):
        self._level = level


class CORSModel(Model):
    def __init__(self, enabled=None, source_route=None, expose_headers=None, allow_headers=None, allow_credentials=None):
        self.swagger_types = {
            'enabled': bool,
            'source_route': str,
            'expose_headers': str,
            'allow_headers': bool,
            'allow_credentials': bool
        }

        self.attribute_map = {
            'enabled': 'enabled',
            'source_route': 'source_route',
            'expose_headers': 'expose_headers',
            'allow_headers': 'allow_headers',
            'allow_credentials': 'allow_credentials'
        }

        self._enabled = enabled
        self._source_route = source_route
        self._expose_headers = expose_headers
        self._allow_headers = allow_headers
        self._allow_credentials = allow_credentials

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def source_route(self):
        return self._source_route

    @source_route.setter
    def source_route(self, source_route):
        self._source_route = source_route

    @property
    def expose_headers(self):
        return self._expose_headers

    @expose_headers.setter
    def expose_headers(self, expose_headers):
        self._expose_headers = expose_headers

    @property
    def allow_headers(self):
        return self._allow_headers

    @allow_headers.setter
    def allow_headers(self, allow_headers):
        self._allow_headers = allow_headers

    @property
    def allow_credentials(self):
        return self._allow_credentials

    @allow_credentials.setter
    def allow_credentials(self, allow_credentials):
        self._allow_credentials = allow_credentials


class CacheModel(Model):
    def __init__(self, enabled=None, time=None):
        self.swagger_types = {
            'enabled': bool,
            'time': float
        }

        self.attribute_map = {
            'enabled': 'enabled',
            'time': 'time'
        }

        self._enabled = enabled
        self._time = time

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, time):
        self._time = time


class AccessModel(Model):
    def __init__(self, max_login_attempts=None, block_time=None, max_request_per_minute=None):
        self.swagger_types = {
            'max_login_attempts': int,
            'block_time': int,
            'max_request_per_minute': int
        }

        self.attribute_map = {
            'max_login_attempts': 'max_login_attempts',
            'block_time': 'block_time',
            'max_request_per_minute': 'max_request_per_minute'
        }

        self._max_login_attempts = max_login_attempts
        self._block_time = block_time
        self._max_request_per_minute = max_request_per_minute

    @property
    def max_login_attempts(self):
        return self._max_login_attempts

    @max_login_attempts.setter
    def max_login_attempts(self, max_login_attempts):
        self._max_login_attempts = max_login_attempts

    @property
    def block_time(self):
        return self._block_time

    @block_time.setter
    def block_time(self, block_time):
        self._block_time = block_time

    @property
    def max_request_per_minute(self):
        return self._max_request_per_minute

    @max_request_per_minute.setter
    def max_request_per_minute(self, max_request_per_minute):
        self._max_request_per_minute = max_request_per_minute


class APIConfigurationModel(Body):
    """API configuration model."""
    def __init__(self, behind_proxy_server=None, https=None, logs=None, cors=None,
                 cache=None, use_only_authd=None, drop_privileges=None, experimental_features=None, access=None):
        self.swagger_types = {
            'behind_proxy_server': bool,
            'https': HTTPSModel,
            'logs': LogsModel,
            'cors': CORSModel,
            'cache': CacheModel,
            'use_only_authd': bool,
            'drop_privileges': bool,
            'experimental_features': bool,
            'access': AccessModel
        }

        self.attribute_map = {
            'behind_proxy_server': 'behind_proxy_server',
            'https': 'https',
            'logs': 'logs',
            'cors': 'cors',
            'cache': 'cache',
            'use_only_authd': 'use_only_authd',
            'drop_privileges': 'drop_privileges',
            'experimental_features': 'experimental_features',
            'access': 'access'
        }

        self._behind_proxy_server = behind_proxy_server
        self._https = https
        self._logs = logs
        self._cors = cors
        self._cache = cache
        self._use_only_authd = use_only_authd
        self._drop_privileges = drop_privileges
        self._experimental_features = experimental_features
        self._access = access

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

    @property
    def access(self):
        return self._access

    @access.setter
    def access(self, access):
        self._access = access


class SecurityConfigurationModel(Body):
    """Security configuration model."""

    def __init__(self, auth_token_exp_timeout: int = None, rbac_mode: str = None):
        self.swagger_types = {
            'auth_token_exp_timeout': int,
            'rbac_mode': str
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
