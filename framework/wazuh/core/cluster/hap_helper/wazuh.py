import logging
import re
import time
from collections import defaultdict
from enum import Enum

import requests
import urllib3
from wazuh_coordinator.exception import WazuhError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # type: ignore


class WazuhAPIMethod(Enum):
    GET = 'get'
    POST = 'post'
    PUT = 'put'
    DELETE = 'delete'


class WazuhAgent:
    RECONNECTION_VERSION_MAJOR = 4
    RECONNECTION_VERSION_MINOR = 3
    AGENT_VERSION_REGEX = re.compile(r'.*v(\d+)\.(\d+)\.\d+')

    @classmethod
    def can_reconnect(cls, agent_version: str) -> bool:
        major, minor = cls.AGENT_VERSION_REGEX.match(agent_version).groups()
        return int(major) >= cls.RECONNECTION_VERSION_MAJOR and int(minor) >= cls.RECONNECTION_VERSION_MINOR

    @classmethod
    def get_agents_able_to_reconnect(cls, agents_list: list[dict]) -> list[str]:
        return [agent['id'] for agent in agents_list if cls.can_reconnect(agent['version'])]


class WazuhAPI:
    AGENTS_MAX_LIMIT = 100000
    API_RETRIES = 5
    TIMEOUT_ERROR_CODE = 3021

    def __init__(
        self,
        address: str,
        logger: logging.Logger,
        port: int = 55000,
        username: str = 'wazuh',
        password: str = 'wazuh',
        excluded_nodes: list | None = None,
    ):
        self.logger = logger
        self.address = address
        self.port = port
        self.username = username
        self.password = password
        self.excluded_nodes = excluded_nodes or []

        self.token = ''

    def initialize(self):
        try:
            requests.get(f'https://{self.address}:{self.port}/', verify=False)
        except requests.ConnectionError:
            raise WazuhError(99, extra_msg='Check connectivity and the configuration file')
        except requests.RequestException as req_exc:
            raise WazuhError(99, extra_msg=req_exc)

    def _obtain_token(self, token_endpoint_method: WazuhAPIMethod = WazuhAPIMethod.GET):
        endpoint = f'https://{self.address}:{self.port}/security/user/authenticate'
        response = getattr(requests, str(token_endpoint_method.value))(
            endpoint, auth=(self.username, self.password), verify=False
        )
        if response.status_code == 200:
            self.token = response.json()['data']['token']
            self.logger.debug(f'Requested API token ({self.username})')
        elif response.status_code == 405:
            self._obtain_token(token_endpoint_method=WazuhAPIMethod.POST)
        elif response.status_code == 401:
            raise WazuhError(102)
        else:
            raise WazuhError(100, extra_msg=f'Full response: {response.status_code} | {response.json()}')

    def _security_headers(self):
        if not self.token:
            self._obtain_token()

        return {'Authorization': f'Bearer {self.token}'}

    def _make_request(
        self,
        endpoint: str,
        method: WazuhAPIMethod = WazuhAPIMethod.GET,
        query_parameters: dict = None,
        json_body: dict = None,
    ) -> dict:
        response = self._retry_request_if_failed(endpoint, method, query_parameters, json_body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            self._obtain_token()
            return self._make_request(endpoint, method=method, query_parameters=query_parameters, json_body=json_body)
        elif response.status_code == 403:
            raise WazuhError(103, extra_msg=f"Endpoint '{endpoint}'")
        else:
            raise WazuhError(101, extra_msg=f'Full response: {response.status_code} | {response.json()}')

    def _retry_request_if_failed(
        self,
        endpoint: str,
        method: WazuhAPIMethod = WazuhAPIMethod.GET,
        query_parameters: dict = None,
        json_body: dict = None,
    ) -> requests.Response:
        last_handled_exception = ''
        uri = f'https://{self.address}:{self.port}{endpoint}'

        for _ in range(self.API_RETRIES):
            try:
                response = getattr(requests, str(method.value))(
                    uri, headers=self._security_headers(), json=json_body, params=query_parameters, verify=False
                )
                self.logger.trace(
                    f"{method.value.upper()} '{endpoint}' - Parameters: {query_parameters or {} }"
                    f' - JSON body: {json_body or {} } [{response.status_code}]'
                )
                if response.status_code == 500:
                    if response.json().get('error', '') == self.TIMEOUT_ERROR_CODE:
                        last_handled_exception = TimeoutError(response.json()['detail'])
                        self.logger.debug('Timeout executing API request')
                    else:
                        last_handled_exception = WazuhError(101, extra_msg=str(response.json()))
                        self.logger.debug('Unexpected error executing API request')
                    time.sleep(1)
                else:
                    return response
            except requests.ConnectionError as request_err:
                last_handled_exception = request_err
                self.logger.debug(f'Could not connect to Wazuh API')
                time.sleep(1)
        else:
            raise WazuhError(104, str(last_handled_exception))

    def get_cluster_nodes(self) -> dict:
        api_response = self._make_request('/cluster/nodes')
        return {
            item['name']: item['ip']
            for item in api_response['data']['affected_items']
            if item['name'] not in self.excluded_nodes
        }

    def reconnect_agents(self, agent_list: list = None) -> dict:
        query_params = None
        if agent_list is not None:
            query_params = {'agents_list': ','.join(agent_list)}

        return self._make_request('/agents/reconnect', method=WazuhAPIMethod.PUT, query_parameters=query_params)

    def get_agents_node_distribution(self) -> dict:
        agent_distribution = defaultdict(list)

        query_params = {
            'select': 'node_name,version',
            'sort': '-version,id',
            'status': 'active',
            'q': 'id!=000',
            'limit': self.AGENTS_MAX_LIMIT,
        }
        api_response = self._make_request('/agents', query_parameters=query_params)

        for agent in api_response['data']['affected_items']:
            agent_distribution[agent['node_name']].append({'id': agent['id'], 'version': agent['version']})

        return agent_distribution

    def get_agents_belonging_to_node(self, node_name: str, limit: int = None) -> list[dict]:
        query_params = {
            'select': 'version',
            'sort': '-version,id',
            'status': 'active',
            'q': 'id!=000',
            'node_name': node_name,
            'limit': limit or self.AGENTS_MAX_LIMIT,
        }
        api_response = self._make_request('/agents', query_parameters=query_params)

        return api_response['data']['affected_items']
