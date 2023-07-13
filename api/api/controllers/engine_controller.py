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
