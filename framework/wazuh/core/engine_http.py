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


class VdHTTPClient:
    """Synchronous HTTP client for the modulesd vulnerability-detector status endpoint."""

    API_URL = 'http://localhost'

    # VD admission rejection reasons ("error" field of a 503 response) mapped to their
    # dedicated WazuhError codes. An unrecognized reason falls back to the generic
    # reserved-block code 8007 rather than a new dedicated code.
    _SCAN_REJECTION_CODES = {
        'vd_not_initialized': 8001,
        'feed_not_ready': 8002,
        'scanner_not_ready': 8003,
        'indexer_unavailable': 8004,
        'scan_queue_full': 8005,
        'shutting_down': 8006,
    }

    def __init__(self, timeout: float = 10):
        self.socket_path = str(common.VD_SOCKET)
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

    def scan_agent(self, agent_id: str) -> None:
        """Request an on-demand vulnerability scan for a single agent.

        Parameters
        ----------
        agent_id : str
            ID of the agent to scan.

        Raises
        ------
        WazuhError
            If VD rejects the scan (mapped to the specific reason when known,
            8007 otherwise) or the request could not be sent.
        WazuhInternalError
            If the modulesd socket could not be reached in time.
        """
        try:
            response = self._client.post(
                url=f'{self.API_URL}/vulnerability-detector/scan',
                json={'agent_id': agent_id},
                headers={'Content-Type': 'application/json'},
            )
        except httpx.TimeoutException as exc:
            raise WazuhInternalError(2025, extra_message=str(exc))
        except httpx.ConnectError as exc:
            raise WazuhInternalError(2026, extra_message=str(exc))
        except httpx.RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))

        if response.is_error:
            reason = None
            try:
                reason = response.json().get('error')
            except ValueError:
                pass

            if reason is None:
                raise WazuhError(2024, extra_message=response.text)

            code = self._SCAN_REJECTION_CODES.get(reason, 8007)
            raise WazuhError(code, extra_message=reason)
