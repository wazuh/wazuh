# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List, Dict, Any, Optional
import json
from os import remove
from os.path import exists

from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.exception import WazuhException, WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.utils import process_array, full_copy, safe_move

from wazuh.core.engine import get_engine_client
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat

from wazuh.core.assets import save_asset_file, generate_asset_file_path

DEFAULT_KVDB_FORMAT = ResourceFormat.JSON
ENGINE_USER_NAMESPACE = 'user'


def _to_policy_type(policy: Optional[str]) -> Optional["PolicyType"]:
    """Map API 'type' query param to engine PolicyType. Defaults to PRODUCTION."""
    return PolicyType.TESTING if policy == 'testing' else PolicyType.PRODUCTION


@expose_resources(actions=['kvdbs:read'], resources=['*:*:*'])
def list_kvdbs(policy_type: Optional[str] = None,
               ids: Optional[List[str]] = None,
               offset: int = 0,
               limit: Optional[int] = None,
               select: Optional[List[str]] = None,
               sort_by: Optional[List[str]] = None,
               sort_ascending: bool = True,
               search_text: Optional[str] = None,
               complementary_search: bool = False,
               search_in_fields: Optional[List[str]] = None,
               q: Optional[str] = None,
               distinct: bool = False) -> AffectedItemsWazuhResult:
    """List or get KVDBs.

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
        with get_engine_client() as client:
            resp = client.content.get_resources(
                type=ResourceType.KVDB,
                name_list=ids or [],
                policy_type=_to_policy_type(policy_type)
            )
            validate_response_or_raise(resp, 8004)

            items: List[Dict[str, Any]] = resp.get('content', [])

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


@expose_resources(actions=['kvdbs:write'], resources=['*:*:*'])
def upsert_kvdb(policy_type: Optional[str] = None,
                item: Optional[Dict[str, Any]] = None) -> AffectedItemsWazuhResult:
    """Create/Update a KVDB in testing policy (mismo flujo que decoders).

    Parameters
    ----------
    policy_type : str, optional
        Must be 'testing' for mutations.
    item : dict, optional
        KVDB item to create/update:
          - type: "kvdb"
          - id: str
          - integration_id: str (optional)
          - name: str
          - content: object (K/V map)

    Returns
    -------
    AffectedItemsWazuhResult
        Confirmation with affected ids.
    """
    result = AffectedItemsWazuhResult(
        all_msg='KVDB upserted successfully',
        none_msg='KVDB not upserted'
    )

    if policy_type != 'testing':
        kvdb_id = (item or {}).get('id', 'unknown')
        result.add_failed_item(id_=kvdb_id, error=WazuhError(4000, 'Mutations only allowed in testing policy'))
        result.total_affected_items = 0
        return result

    kvdb_id = (item or {}).get('id')
    content_obj = (item or {}).get('content')

    if not kvdb_id or not isinstance(content_obj, dict):
        bad_id = kvdb_id or 'unknown'
        result.add_failed_item(id_=bad_id, error=WazuhError(4000, 'Invalid KVDB payload'))
        result.total_affected_items = 0
        return result

    payload = json.dumps(content_obj, ensure_ascii=False)
    pt = _to_policy_type(policy_type)
    asset_file_path = generate_asset_file_path(kvdb_id, pt)

    if not exists(asset_file_path):
        try:
            # Staging file
            save_asset_file(asset_file_path, payload)

            with get_engine_client() as client:
                validation_results = client.catalog.validate_resource(
                    name=kvdb_id,
                    format=DEFAULT_KVDB_FORMAT,
                    content=payload,
                    namespace_id=ENGINE_USER_NAMESPACE
                )
                validate_response_or_raise(validation_results, 8002)

                # Create in Engine
                creation_results = client.content.create_resource(
                    type=ResourceType.KVDB,
                    format=DEFAULT_KVDB_FORMAT,
                    content=payload,
                    policy_type=pt
                )
                validate_response_or_raise(creation_results, 8003)

            result.affected_items.append(kvdb_id)
            result.total_affected_items = 1
            return result

        except WazuhError as exc:
            result.add_failed_item(id_=kvdb_id, error=exc)
            result.total_affected_items = 0
            return result
        except WazuhException as e:
            if getattr(e, 'code', None) == 2802:
                result.total_affected_items = 0
                return result
            raise e
        finally:
            # Staging file cleanup
            exists(asset_file_path) and remove(asset_file_path)

    else:
        backup_file = f'{asset_file_path}.backup'
        try:
            # Backup current file
            try:
                full_copy(asset_file_path, backup_file)
            except IOError as exc:
                raise WazuhError(1019) from exc

            try:
                remove(asset_file_path)
            except IOError as exc:
                raise WazuhError(1907) from exc

            save_asset_file(asset_file_path, payload)

            with get_engine_client() as client:
                validation_results = client.catalog.validate_resource(
                    name=kvdb_id,
                    format=DEFAULT_KVDB_FORMAT,
                    content=payload,
                    namespace_id=ENGINE_USER_NAMESPACE
                )
                validate_response_or_raise(validation_results, 8002)

                # Update in Engine
                update_results = client.content.update_resource(
                    name=kvdb_id,
                    content=payload,
                    policy_type=pt
                )
                validate_response_or_raise(update_results, 8006)

            result.affected_items.append(kvdb_id)

        except WazuhError as exc:
            result.add_failed_item(id_=kvdb_id, error=exc)
        except WazuhException as e:
            if getattr(e, 'code', None) == 2802:
                pass
            else:
                raise e
        finally:
            # Restore backup (idéntico a decoders)
            exists(backup_file) and safe_move(backup_file, asset_file_path)

        result.total_affected_items = len(result.affected_items)
        return result


@expose_resources(actions=['kvdbs:delete'], resources=['*:*:*'])
def delete_kvdbs(policy_type: Optional[str] = None,
                 ids: Optional[List[str]] = None) -> AffectedItemsWazuhResult:
    """Delete one or more KVDBs in testing policy.

    Parameters
    ----------
    policy_type : str, optional
        Must be 'testing' for deletions.
    ids : list[str], optional
        KVDB IDs to delete.

    Returns
    -------
    AffectedItemsWazuhResult
        Confirmation with affected ids.
    """
    # TODO(#31021): Make DELETE all-or-nothing (snapshot→delete→reload; restore on error).
    result = AffectedItemsWazuhResult(
        all_msg='KVDBs deleted successfully',
        none_msg='KVDBs not deleted'
    )

    if policy_type != 'testing':
        for _id in ids or []:
            result.add_failed_item(id_=_id, error=WazuhError(4000, 'Mutations only allowed in testing policy'))
        result.total_affected_items = 0
        return result

    try:
        pt = _to_policy_type(policy_type)
        with get_engine_client() as client:
            for _id in ids or []:
                asset_file_path = generate_asset_file_path(_id, pt)
                backup_file = f'{asset_file_path}.backup'

                try:
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

                    delete_results = client.content.delete_resource(
                        name=_id,
                        policy_type=pt
                    )
                    validate_response_or_raise(delete_results, 8007)

                    result.affected_items.append(_id)

                except WazuhError as exc:
                    result.add_failed_item(id_=_id, error=exc)
                finally:
                    exists(backup_file) and safe_move(backup_file, asset_file_path)

        result.total_affected_items = len(result.affected_items)
        return result

    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            result.total_affected_items = 0
            return result
        raise e
