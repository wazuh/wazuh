# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Quickwit client for querying and managing Quickwit indices."""

import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth


logger = logging.getLogger('wazuh.quickwit')


class QuickwitClient:
    """Client for interacting with Quickwit REST API."""

    def __init__(self, hosts: List[str], username: Optional[str] = None,
                 password: Optional[str] = None, verify_ssl: bool = True,
                 ca_certs: Optional[str] = None, timeout: int = 30):
        """Initialize Quickwit client.

        Args:
            hosts: List of Quickwit host URLs (e.g., ["http://localhost:7280"])
            username: Optional username for authentication
            password: Optional password for authentication
            verify_ssl: Whether to verify SSL certificates
            ca_certs: Path to CA certificate bundle
            timeout: Request timeout in seconds
        """
        self.hosts = hosts
        self.current_host_index = 0
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl if ca_certs is None else ca_certs
        self.timeout = timeout
        self.session = requests.Session()

        if username and password:
            self.session.auth = HTTPBasicAuth(username, password)

    def _get_next_host(self) -> str:
        """Get next available host using round-robin."""
        host = self.hosts[self.current_host_index]
        self.current_host_index = (self.current_host_index + 1) % len(self.hosts)
        return host

    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request to Quickwit.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests

        Returns:
            Response object

        Raises:
            requests.RequestException: If request fails after trying all hosts
        """
        last_exception = None

        # Try all hosts
        for _ in range(len(self.hosts)):
            host = self._get_next_host()
            url = urljoin(host, endpoint)

            try:
                kwargs.setdefault('timeout', self.timeout)
                kwargs.setdefault('verify', self.verify_ssl)
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"Request to {host} failed: {e}")
                last_exception = e
                continue

        raise last_exception or requests.RequestException("All Quickwit hosts failed")

    def search(self, index: str, query: Optional[str] = None,
               max_hits: int = 20, start_offset: int = 0,
               start_timestamp: Optional[int] = None,
               end_timestamp: Optional[int] = None,
               aggregations: Optional[Dict] = None,
               sort_by: Optional[str] = None) -> Dict[str, Any]:
        """Search documents in Quickwit index.

        Args:
            index: Index name to search
            query: Quickwit query string (supports full-text search)
            max_hits: Maximum number of hits to return
            start_offset: Offset for pagination
            start_timestamp: Start timestamp for time-based filtering (Unix timestamp in seconds)
            end_timestamp: End timestamp for time-based filtering (Unix timestamp in seconds)
            aggregations: Aggregation query (JSON object)
            sort_by: Field to sort by (e.g., "timestamp", "-timestamp" for descending)

        Returns:
            Search results as dictionary

        Example:
            >>> client = QuickwitClient(["http://localhost:7280"])
            >>> results = client.search("wazuh-alerts", query="level:high", max_hits=100)
            >>> print(f"Found {results['num_hits']} alerts")
        """
        endpoint = f"/api/v1/{index}/search"

        params = {
            'max_hits': max_hits,
            'start_offset': start_offset
        }

        if query:
            params['query'] = query

        if start_timestamp is not None:
            params['start_timestamp'] = start_timestamp

        if end_timestamp is not None:
            params['end_timestamp'] = end_timestamp

        if aggregations:
            params['aggs'] = json.dumps(aggregations)

        if sort_by:
            params['sort_by'] = sort_by

        response = self._request('GET', endpoint, params=params)
        return response.json()

    def search_post(self, index: str, search_body: Dict[str, Any]) -> Dict[str, Any]:
        """Search using POST method with request body.

        Args:
            index: Index name
            search_body: Complete search request as dictionary

        Returns:
            Search results
        """
        endpoint = f"/api/v1/{index}/search"
        response = self._request('POST', endpoint, json=search_body)
        return response.json()

    def get_index_metadata(self, index: str) -> Dict[str, Any]:
        """Get metadata for an index.

        Args:
            index: Index name

        Returns:
            Index metadata
        """
        endpoint = f"/api/v1/indexes/{index}"
        response = self._request('GET', endpoint)
        return response.json()

    def list_indices(self) -> List[Dict[str, Any]]:
        """List all indices.

        Returns:
            List of index metadata dictionaries
        """
        endpoint = "/api/v1/indexes"
        response = self._request('GET', endpoint)
        return response.json()

    def create_index(self, index_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new index.

        Args:
            index_config: Index configuration following Quickwit schema

        Returns:
            Response from Quickwit

        Example:
            >>> config = {
            ...     "version": "0.7",
            ...     "index_id": "wazuh-alerts",
            ...     "doc_mapping": {
            ...         "field_mappings": [
            ...             {"name": "timestamp", "type": "datetime", "fast": True},
            ...             {"name": "message", "type": "text", "tokenizer": "default"}
            ...         ],
            ...         "timestamp_field": "timestamp"
            ...     }
            ... }
            >>> client.create_index(config)
        """
        endpoint = "/api/v1/indexes"
        response = self._request('POST', endpoint, json=index_config)
        return response.json()

    def delete_index(self, index: str) -> Dict[str, Any]:
        """Delete an index.

        Args:
            index: Index name to delete

        Returns:
            Response from Quickwit
        """
        endpoint = f"/api/v1/indexes/{index}"
        response = self._request('DELETE', endpoint)
        return response.json()

    def cluster_info(self) -> Dict[str, Any]:
        """Get cluster information.

        Returns:
            Cluster information
        """
        endpoint = "/api/v1/cluster"
        response = self._request('GET', endpoint)
        return response.json()

    def health_check(self) -> bool:
        """Check if Quickwit cluster is healthy.

        Returns:
            True if healthy, False otherwise
        """
        try:
            self.cluster_info()
            return True
        except requests.RequestException:
            return False


def create_client_from_config(config: Dict[str, Any]) -> QuickwitClient:
    """Create QuickwitClient from configuration dictionary.

    Args:
        config: Configuration dictionary with keys: hosts, username, password, ssl

    Returns:
        Configured QuickwitClient instance
    """
    hosts = config.get('hosts', ['http://localhost:7280'])
    username = config.get('username')
    password = config.get('password')

    ssl_config = config.get('ssl', {})
    ca_certs = None
    if ssl_config.get('certificate_authorities'):
        ca_certs = ssl_config['certificate_authorities'][0]  # Use first CA cert

    return QuickwitClient(
        hosts=hosts,
        username=username,
        password=password,
        ca_certs=ca_certs
    )
