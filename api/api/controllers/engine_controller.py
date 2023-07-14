import logging
from typing import Optional
from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, remove_nones_to_dict, parse_api_param
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from api.models.base_model_ import Body
from api.models.engine_kvdb_model import DbEntryModel, DbCreationModel
from wazuh import engine_kvdb


logger = logging.getLogger('wazuh-api')

HARDCODED_VALUE_TO_SPECIFY = 100


# TODO add filter query params
def get_kvdb_dbs(request, pretty: bool = False, wait_for_complete: bool = False):
    """
    Retrieves the list of available key-value databases.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response containing the list of available databases.

    Raises:
    -------
    WazuhInternalError:
        If an internal error occurs during the database retrieval.
    """

    f_kwargs = {}
    dapi = DistributedAPI(f=engine_kvdb.get_dbs,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


def create_kvdb_db(request, pretty: bool = False, wait_for_complete: bool = False):
    """
    Creates a new key-value database.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response indicating the success of the database creation.

    Raises:
    -------
    WazuhNotAcceptable:
        If the specified database already exists.
    WazuhInternalError:
        If an internal error occurs during the database creation.
    """

    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await DbCreationModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine_kvdb.create_db,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


def delete_kvdb_db(request, name: str, pretty: bool = False, wait_for_complete: bool = False):
    """
    Deletes a key-value database.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    name: str
        The name of the database to delete.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response indicating the success of the database deletion.

    Raises:
    -------
    WazuhResourceNotFound:
        If the specified database is not found.
    WazuhInternalError:
        If an internal error occurs during the database deletion.
    """

    f_kwargs = {'name': name}
    dapi = DistributedAPI(f=engine_kvdb.delete_db,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


# TODO Add filter query params
def get_kvdb_db_entries(request, name: str, key: Optional[str], pretty: bool = False, wait_for_complete: bool = False):
    """
    Retrieves entries from a key-value database.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    name: str
        The name of the database.
    key: Optional[str]
        Optional key of the entry to retrieve.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response containing the retrieved entries.

    Raises:
    -------
    WazuhResourceNotFound:
        If the specified database or entry is not found.
    WazuhInternalError:
        If an internal error occurs during the retrieval of entries.
    """

    f_kwargs = {'name': name, 'key': key}
    dapi = DistributedAPI(f=engine_kvdb.get_db_entries,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


def create_kvdb_db_entry(request, pretty: bool = False, wait_for_complete: bool = False):
    """
    Creates a new entry in a key-value database.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response indicating the success of the entry creation.

    Raises:
    -------
    WazuhInternalError:
        If an internal error occurs during the entry creation.
    """

    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await DbEntryModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine_kvdb.create_db_entry,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


def update_kvdb_db_entry(request, pretty: bool = False, wait_for_complete: bool = False):
    """
    Updates an existing entry in a key-value database.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response indicating the success of the entry update.

    Raises:
    -------
    WazuhInternalError:
        If an internal error occurs during the entry update.
    """

    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await DbEntryModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine_kvdb.update_db_entry,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


def delete_kvdb_db_entry(request, name: str, key: str, pretty: bool = False, wait_for_complete: bool = False):
    """
    Deletes an entry from a key-value database.

    Parameters:
    -----------
    request: aiohttp.web.Request
        The HTTP request object.
    name: str
        The name of the database.
    key: str
        The key of the entry to delete.
    pretty: bool, optional
        Flag indicating whether the JSON response should be formatted with indentation and line breaks for readability.
    wait_for_complete: bool, optional
        Flag indicating whether to wait for the complete response from the distributed API.

    Returns:
    --------
    aiohttp.web.Response:
        The JSON response indicating the success of the entry deletion.

    Raises:
    -------
    WazuhResourceNotFound:
        If the specified database or entry is not found.
    WazuhInternalError:
        If an internal error occurs during the entry deletion.
    """

    f_kwargs = {'name': name}
    dapi = DistributedAPI(f=engine_kvdb.delete_db_entry,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
