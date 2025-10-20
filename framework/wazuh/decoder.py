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


@expose_resources(actions=["decoders:read"], resources=["*:*:*"])
async def get_decoder(
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
    """Get a list of available decoders."""
    results = AffectedItemsWazuhResult(
        none_msg="No decoder was returned",
        some_msg="Some decoders were not returned",
        all_msg="All selected decoders were returned",
    )
    retrieved_decoders = []
    for id_ in ids or [None]:
        try:
            async with get_engine_client() as client:
                decoder_response = await client.content.get_resources(
                    id_=id_,
                    type=ResourceType.DECODER,
                    policy_type=PolicyType(policy_type),
                )
                validate_response_or_raise(decoder_response, 9003, ResourceType.DECODER)
                retrieved_decoders.extend(decoder_response["content"])
        except WazuhError as exc:
            results.add_failed_item(id_="all" if id_ is None else id_, error=exc)

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
                raise WazuhError(9006)
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
                validate_response_or_raise(delete_results, 9006, ResourceType.DECODER)
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


@expose_resources(actions=["decoders:create", "decoders:update"], resources=["*:*:*"])
async def upsert_decoder(decoder_content: dict, policy_type: str) -> AffectedItemsWazuhResult:
    """Create or update a decoder resource.

    This function will create a new decoder if it does not exist, or update the
    existing one if found.

    Parameters
    ----------
    decoder_content : dict
        Dictionary representing the decoder definition.
    policy_type : str
        The policy type associated with the decoder.

    Returns
    -------
    AffectedItemsWazuhResult
        The result object containing affected and failed items.
    """
    filename = None
    asset_file_path = None
    backup_file = None
    mode = None

    result = AffectedItemsWazuhResult(
        none_msg="Error during decoder handling",
    )

    try:
        decoder_resource = Resource.from_dict(decoder_content)
        filename = decoder_resource.id
        asset_file_path = generate_asset_file_path(filename, PolicyType(policy_type), ResourceType.DECODER)
        file_contents_json = json.dumps(decoder_content)

        # Determine operation mode
        mode = "create" if not exists(asset_file_path) else "update"

        result = AffectedItemsWazuhResult(
            all_msg=f"Decoder was successfully {mode}d",
            none_msg=f"Could not {mode} decoder",
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

        # Write new decoder content
        save_asset_file(asset_file_path, file_contents_json)

        # Validate and push to engine
        async with get_engine_client() as client:
            validation_results = await client.catalog.validate_resource(
                id_=decoder_resource.id,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE,
            )
            validate_response_or_raise(validation_results, 9002, ResourceType.DECODER)

            if mode == "create":
                creation_results = await client.content.create_resource(
                    type=ResourceType.DECODER,
                    resource=decoder_resource,
                    policy_type=policy_type,
                )
                validate_response_or_raise(creation_results, 9004, ResourceType.DECODER)
            else:
                update_results = await client.content.update_resource(
                    type=ResourceType.DECODER,
                    resource=decoder_resource,
                    policy_type=policy_type,
                )
                validate_response_or_raise(update_results, 9005, ResourceType.DECODER)

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
