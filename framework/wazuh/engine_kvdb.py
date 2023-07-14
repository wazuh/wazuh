from typing import Optional

from wazuh.core.wazuh_socket import WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.results import WazuhResult
from wazuh.core.exception import WazuhInternalError, WazuhResourceNotFound, WazuhNotAcceptable
from wazuh.core.common import ENGINE_SOCKET

# TODO Redefine HARDCODED values
HARDCODED_ORIGIN_NAME = "kvdb"
HARDCODED_ORIGIN_MODULE = "kvdb"


def get_dbs():
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, 'kvdb.manager/get', {})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'data': result['dbs']})


def create_db(name: str, path: str):
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name, "json": path}
    msg = create_wazuh_socket_message(origin, 'kvdb.manager/post', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    # TODO Handle error
    if result['status'] == 'ERROR':
        if result['error'] == 'HARD':
            raise WazuhNotAcceptable(9011, extra_message=result['error'])
        else:
            raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})


def delete_db(name: str):
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
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name, "entry": {"value": value, "key": key}}
    msg = create_wazuh_socket_message(origin, 'kvdb.db/put', parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        raise WazuhInternalError(9002, extra_message=result['error'])

    return WazuhResult({'message': result['status']})


def delete_db_entry(name: str):
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {"name": name}
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
