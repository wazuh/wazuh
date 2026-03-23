# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify
# it under the terms of GPLv2

import json

from wazuh.core.common import KEY_STORE_SOCKET
from wazuh.core.wazuh_socket import WazuhSocket


class KeystoreClient:
    """
    Client for Wazuh keystore communication using SizeHeaderProtocol.

    This class manages connection to the Wazuh keystore socket and provides
    methods to perform CRUD operations on the keystore.

    Parameters
    ----------
    logger : logging.Logger, optional
        Logger instance for debugging messages. If not provided,
        debug logging will be disabled.

    Attributes
    ----------
    socket_path : str
        Path to the Unix domain socket for keystore communication
    socket : WazuhSocket or None
        Active socket connection to the keystore

    Raises
    ------
    RuntimeError
        If socket connection cannot be established

    Notes
    -----
    The client uses a custom protocol (SizeHeaderProtocol) where each
    message is prefixed with its size. All operations return JSON-parsed
    responses from the keystore.

    Examples
    --------
    >>> from wazuh.keystore import KeystoreClient
    >>> client = KeystoreClient()
    >>> response = client.put('config', 'my_key', 'my_value')
    >>> print(response)
    {'status': 'success'}

    # Using as a context manager
    >>> with KeystoreClient() as client:
    ...     response = client.get('config', 'my_key')
    ...     print(response)
    {'value': 'my_value', 'status': 'OK'}

    # Using class method connection
    >>> with KeystoreClient.connection() as client:
    ...     response = client.put('config', 'another_key', 'value')
    ...     print(response)
    {'status': 'OK'}
    """

    def __init__(self):
        self.socket_path = KEY_STORE_SOCKET
        self.socket = None
        self._connect()

    def _connect(self):
        """
        Establish connection to the keystore socket.

        Returns
        -------
        None

        Raises
        ------
        RuntimeError
            If socket connection fails
        """
        self.socket = WazuhSocket(self.socket_path)

    def disconnect(self):
        """
        Close the socket connection.

        Returns
        -------
        None

        Notes
        -----
        This method is idempotent and can be called multiple times safely.
        """
        if self.socket:
            self.socket.close()
            self.socket = None

    def __enter__(self):
        """
        Enter the runtime context for the KeystoreClient.

        Returns
        -------
        KeystoreClient
            The instance itself for use in the with statement

        Notes
        -----
        This method is called when entering the 'with' block.
        The connection is already established in __init__.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the runtime context for the KeystoreClient.

        Parameters
        ----------
        exc_type : type or None
            Exception type if an exception was raised
        exc_val : Exception or None
            Exception value if an exception was raised
        exc_tb : traceback or None
            Traceback if an exception was raised

        Returns
        -------
        None

        Notes
        -----
        This method is called when exiting the 'with' block.
        It ensures proper cleanup by calling disconnect().
        If an exception occurred in the with block, it will be
        passed through (not suppressed) since this method returns False.
        """
        self.disconnect()
        # Returning False allows any exception to propagate
        return False

    def send_query(self, query: str):
        """
        Send query to keystore and receive response.

        Parameters
        ----------
        query : str
            Query string in format "COMMAND|COLUMN_FAMILY|KEY|VALUE"

        Returns
        -------
        dict
            JSON-parsed response from keystore

        Raises
        ------
        RuntimeError
            If socket is not connected
        JSONDecodeError
            If response cannot be parsed as JSON

        Notes
        -----
        The method handles UTF-8 encoding/decoding and JSON parsing
        automatically.
        """
        if not self.socket:
            raise RuntimeError("Socket not connected")

        self.socket.send(query.encode("utf-8"))
        response_bytes = self.socket.receive()

        response = response_bytes.decode("utf-8")

        return json.loads(response)

    def put(self, cf, key, value):
        """
        Store a key-value pair in the keystore.

        Parameters
        ----------
        cf : str
            Column family/table name
        key : str
            Key to store
        value : str
            Value to associate with the key

        Returns
        -------
        dict
            Operation result from keystore

        Examples
        --------
        >>> client.put('config', 'api_key', 'secret123')
        {'status': 'OK'}
        """
        return self.send_query(f"PUT|{cf}|{key}|{value}")

    def get(self, cf, key):
        """
        Retrieve a value from the keystore.

        Parameters
        ----------
        cf : str
            Column family/table name
        key : str
            Key to retrieve

        Returns
        -------
        dict
            Value and metadata if key exists

        Notes
        -----
        Returns an error response if the key does not exist.

        Examples
        --------
        >>> client.get('config', 'api_key')
        {'value': 'secret123', 'status': 'OK'}
        """
        return self.send_query(f"GET|{cf}|{key}")

    def delete(self, cf, key):
        """
        Remove a key-value pair from the keystore.

        Parameters
        ----------
        cf : str
            Column family/table name
        key : str
            Key to delete

        Returns
        -------
        dict
            Operation result from keystore

        Examples
        --------
        >>> client.delete('config', 'api_key')
        {'status': 'OK'}
        """
        return self.send_query(f"DELETE|{cf}|{key}")
