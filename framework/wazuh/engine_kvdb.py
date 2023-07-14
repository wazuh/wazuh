from typing import Optional

from wazuh.core.wazuh_socket import WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.results import WazuhResult
from wazuh.core.exception import WazuhInternalError, WazuhResourceNotFound, WazuhNotAcceptable
from wazuh.core.common import ENGINE_SOCKET

# TODO Redefine HARDCODED values
HARDCODED_ORIGIN_NAME = "kvdb"
HARDCODED_ORIGIN_MODULE = "kvdb"


def get_dbs():
    """
    Retrieves the list of available databases.

    Returns:
    ---------
    WazuhResult:
        WazuhResult with the list of available databases under the 'data' key.
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, 'kvdb.manager/get', {})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'data': result['dbs']})


def create_db(name: str, path: str):
    """
     Creates a new database.

     Parameters:
     -----------
     name: str
         Name of the new database.
     path: str
         JSON path of the new database.

     Returns:
     ---------
     WazuhResult:
         WazuhResult with a success message under the 'message' key.

     Raises:
     -------
     WazuhNotAcceptable:
         If the database already exists.
     WazuhInternalError:
         If an internal error occurs.
     """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name, "json": path}
    msg = create_wazuh_socket_message(origin, 'kvdb.manager/post', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    # TODO Handle error
    if result['status'] == 'ERROR':
        if "already exists" in result['error']:
            raise WazuhNotAcceptable(9011, extra_message=result['error'])
        else:
            raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})


def delete_db(name: str):
    """
    Deletes a database.

    Parameters:
    -----------
    name: str
        Name of the database to delete.

    Returns:
    ---------
    WazuhResult:
        WazuhResult with a success message under the 'message' key.

    Raises:
    -------
    WazuhResourceNotFound:
        If the database is not found.
    WazuhInternalError:
        If an internal error occurs.
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name}
    msg = create_wazuh_socket_message(origin, 'kvdb.manager/delete', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if 'not found' in result['error']:
            raise WazuhResourceNotFound(9009, extra_message=result['error'])
        else:
            raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})


def get_db_entries(name: str, key: Optional[str] = None):
    """
    Retrieves entries from a database.

    Parameters:
    -----------
    name: str
        Name of the database.
    key: Optional[str]
        Optional key of the entry to retrieve.

    Returns:
    ---------
    WazuhResult:
        WazuhResult with the retrieved entries under the 'data' key.

    Raises:
    -------
    WazuhResourceNotFound:
        If the database or entry is not found.
    WazuhInternalError:
        If an internal error occurs.
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    if key:
        msg = create_wazuh_socket_message(origin, 'kvdb.db/get', {'name': name, 'key': key})
    else:
        msg = create_wazuh_socket_message(origin, 'kvdb.manager/dump', {'name': name})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if result['status'] == 'ERROR':
            if "Cannot read value: 'NotFound: '" in result['error']:
                raise WazuhResourceNotFound(9010)
            elif 'not found' in result['error']:
                raise WazuhResourceNotFound(9009, extra_message=result['error'])
            else:
                raise WazuhInternalError(9002, extra_message=result['error'])

    if key:
        final_result = [{'value': result['value'], 'key': key}]
    else:
        final_result = result['entries']

    return WazuhResult({'data': final_result})


def create_db_entry(name: str, value: dict, key: str):
    """
    Creates a new entry in a database.

    Parameters:
    -----------
    name: str
        Name of the database.
    value: dict
        Value of the new entry.
    key: str
        Key of the new entry.

    Returns:
    ---------
    WazuhResult:
        WazuhResult with a success message under the 'message' key.

    Raises:
    -------
    WazuhInternalError:
        If an internal error occurs.
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name, "entry": {"value": value, "key": key}}
    msg = create_wazuh_socket_message(origin, 'kvdb.db/put', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})


def update_db_entry(name: str, value: dict, key: str):
    """
    Updates an existing entry in a database.

    Parameters:
    -----------
    name: str
        Name of the database.
    value: dict
        Updated value of the entry.
    key: str
        Key of the entry to update.

    Returns:
    ---------
    WazuhResult:
        WazuhResult with a success message under the 'message' key.

    Raises:
    -------
    WazuhInternalError:
        If an internal error occurs.
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name, "entry": {"value": value, "key": key}}
    msg = create_wazuh_socket_message(origin, 'kvdb.db/put', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})


def delete_db_entry(name: str, key: str):
    """
    Deletes an entry from a database.

    Parameters:
    -----------
    name: str
        Name of the database.
    key: str
        Key of the entry to delete.

    Returns:
    ---------
    WazuhResult:
        WazuhResult with a success message under the 'message' key.

    Raises:
    -------
    WazuhResourceNotFound:
        If the database or entry is not found.
    WazuhInternalError:
        If an internal error occurs.
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name, "key": key}
    msg = create_wazuh_socket_message(origin, 'kvdb.db/delete', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if 'not found' in result['error']:
            raise WazuhResourceNotFound(9009, extra_message=result['error'])
        else:
            raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})
