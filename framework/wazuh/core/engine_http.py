# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import httpx

from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhInternalError


class EngineHTTPClient:
    """Synchronous HTTP client for the Engine API unix socket (analysisd)."""

    API_URL = 'http://localhost'

    def __init__(self, timeout: float = 10):
        self.socket_path = str(common.ANALYSISD_SOCKET)
        try:
            transport = httpx.HTTPTransport(uds=self.socket_path)
            self._client = httpx.Client(transport=transport, timeout=timeout)
        except Exception as exc:
            raise WazuhInternalError(2018, extra_message=str(exc)) from exc

    def close(self) -> None:
        """Close the Engine HTTP client."""
        self._client.close()

    def get_metrics_dump(self) -> dict:
        try:
            response = self._client.post(
                url=f'{self.API_URL}/metrics/dump',
                content='{}',
                headers={'Content-Type': 'application/json'},
            )
        except httpx.TimeoutException as exc:
            raise WazuhInternalError(2020, extra_message=str(exc))
        except httpx.ConnectError as exc:
            raise WazuhInternalError(2021, extra_message=str(exc))
        except httpx.RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))

        if response.is_error:
            raise WazuhError(2019, extra_message=response.text)

        try:
            return response.json()
        except ValueError as exc:
            raise WazuhInternalError(2022, extra_message=f'Invalid JSON in Engine API response: {exc}')

    def get_status(self) -> dict:
        """Retrieve the Engine readiness status from the analysisd socket.

        Returns
        -------
        dict
            The engine status: global `ready` flag plus per-resource state of
            spaces, IOC databases and geo databases.
        """
        try:
            response = self._client.get(
                url=f'{self.API_URL}/status',
                headers={'Content-Type': 'application/json'},
            )
        except httpx.TimeoutException as exc:
            raise WazuhInternalError(2020, extra_message=str(exc))
        except httpx.ConnectError as exc:
            raise WazuhInternalError(2021, extra_message=str(exc))
        except httpx.RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))

        if response.is_error:
            raise WazuhError(2019, extra_message=response.text)

        try:
            return response.json()
        except ValueError as exc:
            raise WazuhInternalError(2022, extra_message=f'Invalid JSON in Engine API response: {exc}')


class ModulesdHTTPClient:
    """Synchronous HTTP client for the modulesd vulnerability-detector status endpoint."""

    API_URL = 'http://localhost'

    def __init__(self, timeout: float = 10):
        self.socket_path = str(common.MODULESD_SOCKET)
        try:
            transport = httpx.HTTPTransport(uds=self.socket_path)
            self._client = httpx.Client(transport=transport, timeout=timeout)
        except Exception as exc:
            raise WazuhInternalError(2023, extra_message=str(exc)) from exc

    def close(self) -> None:
        """Close the modulesd HTTP client."""
        self._client.close()

    def get_status(self) -> dict:
        """Retrieve the vulnerability-detector status from the modulesd socket.

        Returns
        -------
        dict
            Fields: available (bool), status (str), enabled (bool), offset (int),
            last_successful_update (int).
        """
        try:
            response = self._client.get(
                url=f'{self.API_URL}/vulnerability-detector/status',
                headers={'Content-Type': 'application/json'},
            )
        except httpx.TimeoutException as exc:
            raise WazuhInternalError(2025, extra_message=str(exc))
        except httpx.ConnectError as exc:
            raise WazuhInternalError(2026, extra_message=str(exc))
        except httpx.RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))

        if response.is_error:
            raise WazuhError(2024, extra_message=response.text)

        try:
            return response.json()
        except ValueError as exc:
            raise WazuhInternalError(2027, extra_message=f'Invalid JSON in modulesd response: {exc}')
