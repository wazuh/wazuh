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

DEFAULT_DECODER_FORMAT = ResourceFormat.JSON
ENGINE_USER_NAMESPACE = "user"


@expose_resources(actions=["decoders:create"], resources=["*:*:*"])
async def create_decoder(decoder_content: dict, policy_type: str) -> AffectedItemsWazuhResult:
    """Create a new decoder resource."""
    result = AffectedItemsWazuhResult(all_msg="Decoder was successfully uploaded", none_msg="Could not upload decoder")
    filename = None
    try:
        file_contents_json = json.dumps(decoder_content)
        decoder_resource = Resource.from_dict(decoder_content)
        filename = decoder_resource.id
        asset_file_path = generate_asset_file_path(filename, PolicyType(policy_type), ResourceType.DECODER)

        if exists(asset_file_path):
            raise WazuhError(9001)

        save_asset_file(asset_file_path, file_contents_json)

        async with get_engine_client() as client:
            validation_results = await client.catalog.validate_resource(
                id_=decoder_resource.id,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE,
            )
            validate_response_or_raise(validation_results, 9002)

            creation_results = await client.content.create_resource(
                type=ResourceType.DECODER,
                resource=decoder_resource,
                policy_type=policy_type,
            )
            validate_response_or_raise(creation_results, 9003)
            result.affected_items.append(filename)
            result.total_affected_items = len(result.affected_items)
    except WazuhError as exc:
        filename and exists(asset_file_path) and remove(asset_file_path)
        result.add_failed_item(id_=filename or "unknown", error=exc)

    return result


@expose_resources(actions=["decoders:read"], resources=["*:*:*"])
async def get_decoder(
    ids: list,
    policy_type: str,
    status: Status,
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
    """Get a list of available decoders."""
    results = AffectedItemsWazuhResult(
        none_msg="No decoder was returned",
        some_msg="Some decoders were not returned",
        all_msg="All selected decoders were returned",
    )
    retrieved_decoders = []
    for id_ in ids:
        try:
            async with get_engine_client() as client:
                decoder_response = await client.content.get_resources(
                    id_=id_,
                    type=ResourceType.DECODER,
                    policy_type=PolicyType(policy_type),
                )
                validate_response_or_raise(decoder_response, 9004)
                retrieved_decoders.append(decoder_response["content"])
        except WazuhError as exc:
            results.add_failed_item(id_=id_, error=exc)

    parsed_decoders = process_array(
        retrieved_decoders,
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
    results.affected_items = parsed_decoders["items"]
    results.total_affected_items = parsed_decoders["totalItems"]
    return results


@expose_resources(actions=["decoders:update"], resources=["*:*:*"])
async def update_decoder(decoder_content: dict, policy_type: str) -> AffectedItemsWazuhResult:
    """Update an existing decoder resource."""
    result = AffectedItemsWazuhResult(all_msg="Decoder was successfully uploaded", none_msg="Could not upload decoder")
    filename = None
    asset_file_path = None
    backup_file = None

    try:
        decoder_resource = Resource.from_dict(decoder_content)
        filename = decoder_resource.id
        asset_file_path = generate_asset_file_path(filename, PolicyType(policy_type), ResourceType.DECODER)

        # Ensure the decoder file exists before attempting update
        if not exists(asset_file_path):
            raise WazuhError(9005)

        # Create a backup of the current file
        backup_file = f"{asset_file_path}.bak"
        try:
            full_copy(asset_file_path, backup_file)
        except IOError as exc:
            raise WazuhError(1019) from exc

        # Remove the old file before writing the new content
        try:
            remove(asset_file_path)
        except IOError as exc:
            raise WazuhError(1907) from exc

        # Write the updated decoder content
        file_contents_json = json.dumps(decoder_content)
        save_asset_file(asset_file_path, file_contents_json)

        # Validate and update in the engine
        async with get_engine_client() as client:
            validation_results = await client.catalog.validate_resource(
                id_=decoder_resource.id,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE,
            )
            validate_response_or_raise(validation_results, 9002)

            update_results = await client.content.update_resource(
                type=ResourceType.DECODER,
                resource=decoder_resource,
                policy_type=policy_type,
            )
            validate_response_or_raise(update_results, 9006)

        result.affected_items.append(filename)

    except WazuhError as exc:
        # If there is a backup, restore the original file
        backup_file and exists(backup_file) and safe_move(backup_file, asset_file_path)
        result.add_failed_item(id_=filename or "unknown", error=exc)

    finally:
        # Remove the backup
        backup_file and exists(backup_file) and remove(backup_file)
        
    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=["decoders:delete"], resources=["*:*:*"])
async def delete_decoder(ids: List[str], policy_type: str):
    """Delete decoder resources."""
    result = AffectedItemsWazuhResult(
        all_msg="Decoder file was successfully deleted",
        some_msg="Some decoders were not returned",
        none_msg="Could not delete decoder file",
    )
    for id_ in ids:
        backup_file = ""
        asset_file_path = generate_asset_file_path(id_, PolicyType(policy_type), ResourceType.DECODER)
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
                validate_response_or_raise(delete_results, 9007)
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
