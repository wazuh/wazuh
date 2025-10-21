# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from os import remove
from os.path import exists
from typing import List, Optional

from wazuh.rbac.decorators import expose_resources
from wazuh.core.exception import WazuhError
from wazuh.core.engine import get_engine_client
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.engine.models.resources import ResourceFormat, Status, ResourceType, Resource
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.assets import save_asset_file, generate_asset_file_path
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array, full_copy, safe_move

DEFAULT_INTEGRATION_FORMAT = ResourceFormat.JSON
ENGINE_USER_NAMESPACE = "user"

@expose_resources(actions=["integrations:read"], resources=["*:*:*"])
async def get_integration(
    ids: list,
    policy_type: str,
    status: Optional[Status] = None,
    offset: Optional[int] = 0,
    limit: Optional[int] = 0,
    select: Optional[list] = None,
    sort_by: Optional[list] = None,
    sort_ascending: Optional[bool] = True,
    search_text: Optional[str] = None,
    complementary_search: Optional[bool] = False,
    search_in_fields: Optional[list] = None,
    q: Optional[str] = "",
    distinct: Optional[bool] = False,
) -> AffectedItemsWazuhResult:
    """Get a list of available integrations."""
    results = AffectedItemsWazuhResult(
        none_msg="No integration was returned",
        some_msg="Some integrations were not returned",
        all_msg="All selected integrations were returned",
    )
    retrieved_integrations = []
    for id_ in (ids or [None]):
        try:
            async with get_engine_client() as client:
                integration_response = await client.content.get_resources(
                    id_=id_,
                    type=ResourceType.INTEGRATION,
                    policy_type=PolicyType(policy_type),
                )
                validate_response_or_raise(integration_response, 9003, ResourceType.INTEGRATION)
                retrieved_integrations.extend(integration_response["content"])
        except WazuhError as exc:
            results.add_failed_item(id_="all" if id_ is None else id_, error=exc)

    parsed_integrations = process_array(
        retrieved_integrations,
        search_text=search_text,
        search_in_fields=search_in_fields,
        complementary_search=complementary_search,
        sort_by=sort_by,
        sort_ascending=sort_ascending,
        offset=offset,
        select=select,
        limit=limit,
        q=q,
        distinct=distinct,
    )
    results.affected_items = parsed_integrations["items"]
    results.total_affected_items = parsed_integrations["totalItems"]
    return results


@expose_resources(actions=["integrations:delete"], resources=["*:*:*"])
async def delete_integration(ids: List[str], policy_type: str):
    """Delete integration resources."""
    result = AffectedItemsWazuhResult(
        all_msg="Integration file was successfully deleted",
        some_msg="Some integrations were not returned",
        none_msg="Could not delete integration file",
    )
    for id_ in ids:
        backup_file = ""
        asset_file_path = generate_asset_file_path(id_, PolicyType(policy_type), ResourceType.INTEGRATION)
        try:
            if not exists(asset_file_path):
                raise WazuhError(9005)
            backup_file = f"{asset_file_path}.backup"
            try:
                full_copy(asset_file_path, backup_file)
            except IOError as exc:
                raise WazuhError(1019) from exc
            try:
                remove(asset_file_path)
            except IOError as exc:
                raise WazuhError(1907) from exc
            async with get_engine_client() as client:
                delete_results = await client.content.delete_resource(id_=id_, policy_type=PolicyType(policy_type))
                validate_response_or_raise(delete_results, 9007, ResourceType.INTEGRATION)
            result.affected_items.append(id_)
        except WazuhError as exc:
            # Restore the backup
            backup_file and exists(backup_file) and safe_move(backup_file, asset_file_path)
            result.add_failed_item(id_=id_, error=exc)
        finally:
            # Remove the backup
            backup_file and exists(backup_file) and remove(backup_file)

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=["integrations:create", "integrations:update"], resources=["*:*:*"])
async def upsert_integration(integration_content: dict, policy_type: str) -> AffectedItemsWazuhResult:
    """Create or update an integration resource."""
    filename = None
    asset_file_path = None
    backup_file = None
    mode = None

    result = AffectedItemsWazuhResult(
        none_msg="Error during integration handling",
    )

    try:
        integration_resource = Resource.from_dict(integration_content)
        filename = integration_resource.id
        asset_file_path = generate_asset_file_path(
            filename, PolicyType(policy_type), ResourceType.INTEGRATION
        )
        file_contents_json = json.dumps(integration_content)

        # Determine operation mode
        mode = "create" if not exists(asset_file_path) else "update"

        result = AffectedItemsWazuhResult(
            all_msg=f"Integration was successfully {mode}d",
            none_msg=f"Could not {mode} integration",
        )

        if mode == "update":
            backup_file = f"{asset_file_path}.bak"
            try:
                full_copy(asset_file_path, backup_file)
            except IOError as exc:
                raise WazuhError(1019) from exc

            try:
                remove(asset_file_path)
            except IOError as exc:
                raise WazuhError(1907) from exc

        # Write new integration content
        save_asset_file(asset_file_path, file_contents_json)

        # Validate and push to engine
        async with get_engine_client() as client:
            validation_results = await client.catalog.validate_resource(
                id_=integration_resource.id,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE,
            )
            validate_response_or_raise(validation_results, 9002, ResourceType.INTEGRATION)

            if mode == "create":
                creation_results = await client.content.create_resource(
                    type=ResourceType.INTEGRATION,
                    resource=integration_resource,
                    policy_type=policy_type,
                )
                validate_response_or_raise(creation_results, 9004, ResourceType.INTEGRATION)
            else:
                update_results = await client.content.update_resource(
                    type=ResourceType.INTEGRATION,
                    resource=integration_resource,
                    policy_type=policy_type,
                )
                validate_response_or_raise(update_results, 9005, ResourceType.INTEGRATION)

        result.affected_items.append(filename)

    except WazuhError as exc:
        # Restore previous backup if it exists
        if backup_file and exists(backup_file):
            safe_move(backup_file, asset_file_path)
        elif mode == "create" and asset_file_path and exists(asset_file_path):
            remove(asset_file_path)

        result.add_failed_item(id_=filename or "unknown", error=exc)

    finally:
        # Remove leftover backup safely
        if backup_file and exists(backup_file):
            remove(backup_file)

    result.total_affected_items = len(result.affected_items)
    return result
