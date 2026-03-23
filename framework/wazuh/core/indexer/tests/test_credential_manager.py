# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

import pytest

from wazuh.core.indexer.credential_manager import KeystoreClient


class TestKeystoreClientInit(TestCase):
    """
    Tests for the KeystoreClient initialization process.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_init_creates_socket_connection(self, mock_socket_class):
        """
        Verify that __init__ successfully creates a WazuhSocket connection.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        assert client.socket is not None
        assert client.socket == mock_socket
        mock_socket_class.assert_called_once()

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_init_sets_socket_path(self, mock_socket_class):
        """
        Verify that __init__ uses the correct path from KEY_STORE_SOCKET.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        with patch("wazuh.core.indexer.credential_manager.KEY_STORE_SOCKET", "/custom/path"):
            client = KeystoreClient()
            mock_socket_class.assert_called_once_with("/custom/path")

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_init_socket_connection_error(self, mock_socket_class):
        """
        Verify that KeystoreClient raises RuntimeError if the socket connection fails.
        """
        mock_socket_class.side_effect = RuntimeError("Connection failed")

        with pytest.raises(RuntimeError):
            KeystoreClient()


class TestKeystoreClientDisconnect(TestCase):
    """
    Tests for the KeystoreClient disconnect method.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_disconnect_closes_socket(self, mock_socket_class):
        """
        Verify that disconnect closes the socket and cleans up the reference.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        client.disconnect()

        mock_socket.close.assert_called_once()
        assert client.socket is None

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_disconnect_when_no_socket(self, mock_socket_class):
        """
        Verify that disconnect handles cases where the socket is already None.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        client.socket = None

        client.disconnect()
        mock_socket.close.assert_not_called()

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_disconnect_idempotent(self, mock_socket_class):
        """
        Verify that disconnect is idempotent and can be called multiple times.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        client.disconnect()
        client.disconnect()

        mock_socket.close.assert_called_once()


class TestKeystoreClientContextManager(TestCase):
    """
    Tests for KeystoreClient when used as a Context Manager.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_enter_returns_self(self, mock_socket_class):
        """
        Verify that __enter__ returns the instance itself.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.__enter__()

        assert result is client

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_exit_calls_disconnect(self, mock_socket_class):
        """
        Verify that __exit__ closes the connection.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.__exit__(None, None, None)

        mock_socket.close.assert_called_once()
        assert result is False

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_exit_propagates_exception(self, mock_socket_class):
        """
        Verify that __exit__ does not suppress exceptions (returns False).
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        exc_type = ValueError
        exc_val = ValueError("test error")
        exc_tb = None

        result = client.__exit__(exc_type, exc_val, exc_tb)

        assert result is False

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_context_manager_usage(self, mock_socket_class):
        """
        Verify standard 'with' statement usage for KeystoreClient.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        with KeystoreClient() as client:
            assert client is not None
            assert isinstance(client, KeystoreClient)

        mock_socket.close.assert_called_once()


class TestKeystoreClientSendQuery(TestCase):
    """
    Tests for the send_query method in KeystoreClient.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_send_query_success(self, mock_socket_class):
        """
        Verify successful query transmission and response parsing.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK", "value": "test_value"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.send_query("GET|config|key1")

        assert result == response_dict
        mock_socket.send.assert_called_once_with(b"GET|config|key1")

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_send_query_no_socket(self, mock_socket_class):
        """
        Verify that send_query raises RuntimeError if called without a connection.
        """
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        client.socket = None

        with pytest.raises(RuntimeError) as exc_info:
            client.send_query("GET|config|key1")

        assert "Socket not connected" in str(exc_info.value)

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_send_query_invalid_json_response(self, mock_socket_class):
        """
        Verify that send_query raises JSONDecodeError if response is malformed.
        """
        mock_socket = MagicMock()
        mock_socket.receive.return_value = b"invalid json{{{{"
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        with pytest.raises(json.JSONDecodeError):
            client.send_query("GET|config|key1")

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_send_query_utf8_encoding(self, mock_socket_class):
        """
        Verify that send_query correctly handles UTF-8 characters in queries.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        query_with_unicode = "GET|config|κλειδί"

        client.send_query(query_with_unicode)

        mock_socket.send.assert_called_once_with(query_with_unicode.encode("utf-8"))

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_send_query_complex_json_response(self, mock_socket_class):
        """
        Verify that send_query handles nested JSON responses correctly.
        """
        mock_socket = MagicMock()
        response_dict = {
            "status": "OK",
            "data": {
                "nested": {"value": "test"},
                "array": [1, 2, 3],
            },
        }
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.send_query("GET|config|complex_key")

        assert result == response_dict


class TestKeystoreClientPut(TestCase):
    """
    Tests for the 'put' operation in KeystoreClient.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_put_success(self, mock_socket_class):
        """
        Verify successful PUT command formatting and execution.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.put("config", "api_key", "secret123")

        assert result == response_dict
        mock_socket.send.assert_called_once_with(
            b"PUT|config|api_key|secret123"
        )

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_put_with_special_characters(self, mock_socket_class):
        """
        Verify PUT command when values contain special characters.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        special_value = "p@ssw0rd!#$%"
        result = client.put("creds", "password", special_value)

        assert result == response_dict
        expected_query = f"PUT|creds|password|{special_value}".encode("utf-8")
        mock_socket.send.assert_called_once_with(expected_query)

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_put_multiple_operations(self, mock_socket_class):
        """
        Verify multiple sequential PUT operations.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        client.put("config", "key1", "value1")
        client.put("config", "key2", "value2")
        client.put("other", "key3", "value3")

        assert mock_socket.send.call_count == 3


class TestKeystoreClientGet(TestCase):
    """
    Tests for the 'get' operation in KeystoreClient.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_get_success(self, mock_socket_class):
        """
        Verify successful GET command and value retrieval.
        """
        mock_socket = MagicMock()
        response_dict = {"value": "secret123", "status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.get("config", "api_key")

        assert result == response_dict
        assert result["value"] == "secret123"
        mock_socket.send.assert_called_once_with(b"GET|config|api_key")

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_get_key_not_found(self, mock_socket_class):
        """
        Verify GET command response when a key does not exist.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "ERROR", "error": "Key not found"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.get("config", "nonexistent")

        assert result["status"] == "ERROR"

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_get_multiple_keys(self, mock_socket_class):
        """
        Verify multiple sequential GET operations.
        """
        mock_socket = MagicMock()
        response_dict = {"value": "test_value", "status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        result1 = client.get("config", "key1")
        result2 = client.get("config", "key2")
        result3 = client.get("other", "key3")

        assert result1 == result2 == result3 == response_dict
        assert mock_socket.send.call_count == 3


class TestKeystoreClientDelete(TestCase):
    """
    Tests for the 'delete' operation in KeystoreClient.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_delete_success(self, mock_socket_class):
        """
        Verify successful DELETE command formatting.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.delete("config", "api_key")

        assert result == response_dict
        mock_socket.send.assert_called_once_with(b"DELETE|config|api_key")

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_delete_nonexistent_key(self, mock_socket_class):
        """
        Verify DELETE behavior when targeting a non-existent key.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "ERROR"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()
        result = client.delete("config", "nonexistent")

        assert result["status"] == "ERROR"

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_delete_multiple_keys(self, mock_socket_class):
        """
        Verify multiple sequential DELETE operations.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        client.delete("config", "key1")
        client.delete("config", "key2")
        client.delete("other", "key3")

        assert mock_socket.send.call_count == 3


class TestKeystoreClientCRUDWorkflow(TestCase):
    """
    Tests for the complete lifecycle (CRUD) using KeystoreClient.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_crud_workflow(self, mock_socket_class):
        """
        Verify a full Create, Read, Update, Delete workflow.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        with KeystoreClient() as client:
            # Create
            create_result = client.put("config", "test_key", "initial_value")
            assert create_result["status"] == "OK"

            # Read
            read_result = client.get("config", "test_key")
            assert read_result["status"] == "OK"

            # Update
            update_result = client.put("config", "test_key", "updated_value")
            assert update_result["status"] == "OK"

            # Delete
            delete_result = client.delete("config", "test_key")
            assert delete_result["status"] == "OK"

        mock_socket.close.assert_called_once()


class TestKeystoreClientEdgeCases(TestCase):
    """
    Tests for edge cases and boundary conditions.
    """

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_empty_string_values(self, mock_socket_class):
        """
        Verify that PUT handles empty strings for keys and values.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        client.put("config", "", "")
        mock_socket.send.assert_called_with(b"PUT|config||")

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_large_values(self, mock_socket_class):
        """
        Verify that the client handles large data payloads.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        large_value = "x" * 10000
        result = client.put("config", "large_key", large_value)

        assert result["status"] == "OK"
        assert mock_socket.send.call_count == 1

    @patch("wazuh.core.indexer.credential_manager.WazuhSocket")
    def test_pipe_character_in_value(self, mock_socket_class):
        """
        Verify that the pipe character ('|') is handled within values.
        """
        mock_socket = MagicMock()
        response_dict = {"status": "OK"}
        mock_socket.receive.return_value = json.dumps(response_dict).encode("utf-8")
        mock_socket_class.return_value = mock_socket

        client = KeystoreClient()

        value_with_pipes = "value|with|pipes"
        result = client.put("config", "key", value_with_pipes)

        assert result["status"] == "OK"
        expected_query = f"PUT|config|key|{value_with_pipes}".encode("utf-8")
        mock_socket.send.assert_called_once_with(expected_query)
