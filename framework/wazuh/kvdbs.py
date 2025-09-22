# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List, Dict, Any, Optional
import json

from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.exception import WazuhException, WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.utils import process_array

from wazuh.core.engine import get_engine_client
from wazuh.core.engine.content import ContentModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat


def _to_policy_type(policy: Optional[str]) -> Optional["PolicyType"]:
    if PolicyType is None:
        return None
    # Default to PRODUCTION on None/others; only 'testing' goes to testing
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
    result = AffectedItemsWazuhResult(all_msg='KVDBs were returned',
                                      some_msg='Some KVDBs were not returned',
                                      none_msg='No KVDB was returned')
    try:
        with get_engine_client() as client:
            resp = client.run(client.content.get_resources(
                type=ResourceType.KVDB,
                name_list=ids or [],
                policy_type=_to_policy_type(policy_type)
            ))
            items: List[Dict[str, Any]] = resp.get('content', [])

        processed = process_array(items,
                                  search_text=search_text,
                                  search_in_fields=search_in_fields or ['id', 'name', 'integration_id'],
                                  complementary_search=complementary_search,
                                  sort_by={'fields': sort_by or ['id']},
                                  sort_ascending=sort_ascending,
                                  offset=offset,
                                  limit=limit,
                                  select=select,
                                  q=q,
                                  distinct=distinct)
        result.affected_items = processed['items']
        result.total_affected_items = processed['totalItems']
        return result

    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            # placeholder mode: no engine yet
            result.affected_items = []
            result.total_affected_items = 0
            return result
        raise e


@expose_resources(actions=['kvdbs:write'], resources=['*:*:*'])
def upsert_kvdb(policy_type: Optional[str] = None,
                item: Optional[Dict[str, Any]] = None) -> AffectedItemsWazuhResult:
    """Create/Update a KVDB in testing policy.

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
    result = AffectedItemsWazuhResult(all_msg='KVDB upserted successfully',
                                      none_msg='KVDB not upserted')

    if policy_type != 'testing':
        kvdb_id = (item or {}).get('id', 'unknown')
        result.add_failed_item(id_=kvdb_id, error=WazuhError(4000, 'Mutations only allowed in testing policy'))
        result.total_affected_items = 0
        return result

    try:

        kvdb_id = (item or {}).get('id')
        content_obj = (item or {}).get('content')

        # Minimal payload validation (helps tests and avoids engine errors)
        if not kvdb_id or not isinstance(content_obj, dict):
            bad_id = kvdb_id or 'unknown'
            result.add_failed_item(id_=bad_id, error=WazuhError(4000, 'Invalid KVDB payload'))
            result.total_affected_items = 0
            return result

        payload = json.dumps(content_obj, ensure_ascii=False)

        with get_engine_client() as client:
            pt = _to_policy_type(policy_type)

            # Idempotent: try update; if not found → create
            try:
                client.run(client.content.update_resource(name=kvdb_id, content=payload, policy_type=pt))
            except Exception:
                client.run(client.content.create_resource(
                    type=ResourceType.KVDB,
                    format=ResourceFormat.JSON,
                    content=payload,
                    policy_type=pt
                ))

        result.affected_items.append(kvdb_id)
        result.total_affected_items = 1
        return result

    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            result.total_affected_items = 0
            return result
        raise e


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
    result = AffectedItemsWazuhResult(all_msg='KVDBs deleted successfully',
                                      none_msg='KVDBs not deleted')

    if policy_type != 'testing':
        for _id in ids or []:
            result.add_failed_item(id_=_id, error=WazuhError(4000, 'Mutations only allowed in testing policy'))
        result.total_affected_items = 0
        return result

    try:
        if get_engine_client is None or ContentModule is None:
            raise WazuhException(2802)

        with get_engine_client() as client:
            pt = _to_policy_type(policy_type)
            for _id in ids or []:
                client.run(client.content.delete_resource(name=_id, policy_type=pt))

        result.affected_items.extend(ids or [])
        result.total_affected_items = len(result.affected_items)
        return result

    except WazuhException as e:
        if getattr(e, 'code', None) == 2802:
            result.total_affected_items = 0
            return result
        raise e

