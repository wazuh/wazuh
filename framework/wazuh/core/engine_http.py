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
        transport = httpx.HTTPTransport(uds=self.socket_path)
        self._client = httpx.Client(transport=transport, timeout=timeout)

    def close(self) -> None:
        """Close the Engine HTTP client."""
        self._client.close()

    def get_metrics_dump(self) -> dict:
        """Fetch all engine metrics via the /metrics/dump endpoint.

        Returns
        -------
        dict
            Raw Dump_Response JSON from the Engine API.
        """
        try:
            response = self._client.post(
                url=f'{self.API_URL}/metrics/dump',
                content='{}',
                headers={'Content-Type': 'text/plain'},
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
        except Exception as exc:
            raise WazuhError(2019, extra_message=f'Invalid JSON in Engine API response: {exc}')
