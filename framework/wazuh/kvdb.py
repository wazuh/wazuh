# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Any
import json
import os
from os import remove
from os.path import exists

from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.exception import WazuhException, WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.utils import process_array, full_copy, safe_move
from wazuh.core.common import USER_TESTING_KVDB_PATH, USER_PRODUCTION_KVDB_PATH

from wazuh.core.engine import get_engine_client
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat

from wazuh.core.assets import save_asset_file

DEFAULT_KVDB_FORMAT = ResourceFormat.JSON
ENGINE_USER_NAMESPACE = 'user'


def _to_policy_type(policy: str | None) -> PolicyType:
    """Map API 'type' query param to engine PolicyType. Defaults to PRODUCTION."""
    return PolicyType.TESTING if policy == 'testing' else PolicyType.PRODUCTION


def generate_kvdb_file_path(resource_id: str, policy_type: PolicyType) -> str:
    """Build the absolute path for a KVDB JSON file under the given policy.

    Parameters
    ----------
    resource_id : str
        KVDB identifier (filename without extension).
    policy_type : PolicyType
        TESTING or PRODUCTION scope.

    Returns
    -------
    str
        Full path to '<base>/resource_id.json'.

    Raises
    ------
    WazuhError
        1907 if the base directory is missing or not writable.
    """
    base_dir = USER_TESTING_KVDB_PATH if policy_type == PolicyType.TESTING else USER_PRODUCTION_KVDB_PATH
    if not os.path.isdir(base_dir):
        raise WazuhError(1907, f"KVDB base directory not found: '{base_dir}'")
    if not os.access(base_dir, os.W_OK):
        raise WazuhError(1907, f"KVDB base directory not writable: '{base_dir}'")
    return os.path.join(base_dir, f"{resource_id}.json")

@expose_resources(actions=['kvdbs:read'], resources=['*:*:*'])
async def list_kvdbs(policy_type: str | None = None,
                     ids: list[str] | None = None,
                     offset: int = 0,
                     limit: int | None = None,
                     select: list[str] | None = None,
                     sort_by: list[str] | None = None,
                     sort_ascending: bool = True,
                     search_text: str | None = None,
                     complementary_search: bool = False,
                     search_in_fields: list[str] | None = None,
                     q: str | None = None,
                     distinct: bool = False) -> AffectedItemsWazuhResult:
    """List KVDB resources.

    Parameters
    ----------
    policy_type : str, optional
        'testing' | 'production'. Default: production.
    ids : list[str], optional
        Filter by KVDB IDs (engine names).
    offset : int
        First item to return.
    limit : int, optional
        Max number of items to return.
    select : list, optional
        Fields to return.
    sort_by : list, optional
        Fields to sort by (default: ['id']).
    sort_ascending : bool
        Sort ascending (True) or descending (False).
    search_text : str, optional
        Search string.
    complementary_search : bool
        If True, invert search (NOT contains).
    search_in_fields : list, optional
        Fields where to apply search_text (default: ['id','name','integration_id']).
    q : str, optional
        Advanced query filter.
    distinct : bool
        Return distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        KVDBs collection.
    """
    result = AffectedItemsWazuhResult(
        all_msg='KVDBs were returned',
        some_msg='Some KVDBs were not returned',
        none_msg='No KVDB was returned'
    )

    try:
        async with get_engine_client() as client:
            resp = await client.content.get_resources(
                type=ResourceType.KVDB,
                name_list=ids or [],
                policy_type=_to_policy_type(policy_type)
            )
            validate_response_or_raise(resp, 8004)

            items: list[dict[str, Any]] = resp.get('content', [])
            for it in items:
                it.setdefault('type', ResourceType.KVDB.value)

        processed = process_array(
            items,
            search_text=search_text,
            search_in_fields=search_in_fields or ['id', 'name', 'integration_id'],
            complementary_search=complementary_search,
            sort_by=sort_by or ['id'],
            sort_ascending=sort_ascending,
            offset=offset,
            limit=limit,
            select=select,
            q=q,
            distinct=distinct
        )
        result.affected_items = processed['items']
        result.total_affected_items = processed['totalItems']
        return result

    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            result.affected_items = []
            result.total_affected_items = 0
            return result
        raise e


@expose_resources(actions=['kvdbs:create'], resources=['*:*:*'])
async def create_kvdb(policy_type: str,
                      item: dict[str, Any]) -> AffectedItemsWazuhResult:
    """Create a KVDB.

    Parameters
    ----------
    policy_type : str
        Must be 'testing' for mutations.
    item : dict
        KVDB item to create:
          - id: str
          - integration_id: str (optional)
          - name: str
          - content: object (K/V map)

    Returns
    -------
    AffectedItemsWazuhResult
        Confirmation with affected ids (or failed_items if exists/error).
    """
    if policy_type != 'testing':
        raise WazuhError(4000, 'Mutations only allowed in testing policy')
    if not item:
        raise WazuhError(4000, 'Missing request body')

    result = AffectedItemsWazuhResult(
        all_msg='KVDB was successfully created',
        none_msg='Could not create KVDB'
    )

    kvdb_id = item.get('id')
    display_name = item.get('name')
    content_obj = item.get('content')
    integration_id = item.get('integration_id')

    if not kvdb_id or not isinstance(content_obj, dict):
        raise WazuhError(4000, 'Invalid KVDB payload')

    payload = json.dumps(content_obj, ensure_ascii=False)
    pt = _to_policy_type(policy_type)
    asset_file_path = generate_kvdb_file_path(kvdb_id, pt)

    created_ok = False
    try:
        # Fail if file already exists
        if exists(asset_file_path):
            raise WazuhError(8001)

        # Write staged file on disk
        save_asset_file(asset_file_path, payload)

        # Validate and create in Engine
        async with get_engine_client() as client:
            validation_results = await client.catalog.validate_resource(
                name=kvdb_id,
                format=DEFAULT_KVDB_FORMAT,
                content=payload,
                namespace_id=ENGINE_USER_NAMESPACE
            )
            validate_response_or_raise(validation_results, 8002)

            creation_results = await client.content.create_resource(
                type=ResourceType.KVDB,
                format=DEFAULT_KVDB_FORMAT,
                content=payload,
                policy_type=pt,
                name=kvdb_id,
                integration_id=integration_id,
                display_name=display_name
            )
            validate_response_or_raise(creation_results, 8003)

        # Keep the file on disk when successful
        created_ok = True
        result.affected_items.append(kvdb_id)
        result.total_affected_items = 1

    except WazuhError:
        raise
    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            result.total_affected_items = 0
        else:
            raise e
    finally:
        if not created_ok and exists(asset_file_path):
            remove(asset_file_path)

    return result


@expose_resources(actions=['kvdbs:update'], resources=['*:*:*'])
async def update_kvdb(policy_type: str,
                      item: dict[str, Any]) -> AffectedItemsWazuhResult:
    """Update an existing KVDB.

    Parameters
    ----------
    policy_type : str
        Must be 'testing' for mutations.
    item : dict
        KVDB item to update:
          - id: str
          - integration_id: str (optional)
          - name: str (optional)
          - content: object (K/V map)

    Returns
    -------
    AffectedItemsWazuhResult
        Confirmation with affected ids.
    """
    if policy_type != 'testing':
        raise WazuhError(4000, 'Mutations only allowed in testing policy')
    if not item:
        raise WazuhError(4000, 'Missing request body')

    result = AffectedItemsWazuhResult(
        all_msg='KVDB was successfully updated',
        none_msg='Could not update KVDB'
    )

    kvdb_id = item.get('id')
    display_name = item.get('name')
    content_obj = item.get('content')

    if not kvdb_id or not isinstance(content_obj, dict):
        raise WazuhError(4000, 'Invalid KVDB payload')

    payload = json.dumps(content_obj, ensure_ascii=False)
    pt = _to_policy_type(policy_type)
    asset_file_path = generate_kvdb_file_path(kvdb_id, pt)

    backup_file = ''
    updated_ok = False
    try:
        # Must exist to update
        if not exists(asset_file_path):
            raise WazuhError(8005)

        # Backup current file, replace on disk, then validate and update in Engine
        backup_file = f'{asset_file_path}.backup'
        try:
            full_copy(asset_file_path, backup_file)
        except IOError as exc:
            raise WazuhError(1019) from exc

        try:
            remove(asset_file_path)
        except IOError as exc:
            raise WazuhError(1907) from exc

        save_asset_file(asset_file_path, payload)

        async with get_engine_client() as client:
            validation_results = await client.catalog.validate_resource(
                name=kvdb_id,
                format=DEFAULT_KVDB_FORMAT,
                content=payload,
                namespace_id=ENGINE_USER_NAMESPACE
            )
            validate_response_or_raise(validation_results, 8002)

            update_results = await client.content.update_resource(
                name=kvdb_id,
                content=payload,
                policy_type=pt,
                display_name=display_name
            )
            validate_response_or_raise(update_results, 8006)

        updated_ok = True
        result.affected_items.append(kvdb_id)

    except WazuhError:
        raise
    except WazuhException as e:
        if getattr(e, 'code', None) != 2802:
            raise e
    finally:
        if exists(backup_file):
            if not updated_ok:
                safe_move(backup_file, asset_file_path)
            else:
                remove(backup_file)

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=['kvdbs:delete'], resources=['*:*:*'])
async def delete_kvdbs(policy_type: str,
                       ids: list[str]) -> AffectedItemsWazuhResult:
    """Delete one or more KVDBs.

    Parameters
    ----------
    policy_type : str
        Must be 'testing' for deletions.
    ids : list[str]
        KVDB IDs to delete.

    Returns
    -------
    AffectedItemsWazuhResult
        Confirmation with affected ids.
    """
    if policy_type != 'testing':
        raise WazuhError(4000, 'Mutations only allowed in testing policy')
    if not ids:
        raise WazuhError(4000, 'Missing ids to delete')

    result = AffectedItemsWazuhResult(
        all_msg='KVDBs deleted successfully',
        none_msg='KVDBs not deleted'
    )

    try:
        pt = _to_policy_type(policy_type)
        async with get_engine_client() as client:
            for kvdb_id in ids:
                asset_file_path = generate_kvdb_file_path(kvdb_id, pt)
                backup_file = f'{asset_file_path}.backup'
                deleted_ok = False

                try:
                    # File must exist to delete
                    if not exists(asset_file_path):
                        raise WazuhError(8005)

                    try:
                        full_copy(asset_file_path, backup_file)
                    except IOError as exc:
                        raise WazuhError(1019) from exc

                    try:
                        remove(asset_file_path)
                    except IOError as exc:
                        raise WazuhError(1907) from exc

                    delete_results = await client.content.delete_resource(
                        name=kvdb_id,
                        policy_type=pt
                    )
                    validate_response_or_raise(delete_results, 8007)

                    deleted_ok = True
                    result.affected_items.append(kvdb_id)

                except WazuhError as exc:
                    result.add_failed_item(id_=kvdb_id, error=exc)
                finally:
                    if exists(backup_file):
                        if not deleted_ok:
                            # Restore file on failure
                            safe_move(backup_file, asset_file_path)
                        else:
                            # Cleanup backup on success
                            remove(backup_file)

        result.total_affected_items = len(result.affected_items)
        return result

    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            result.total_affected_items = 0
            return result
        raise e
