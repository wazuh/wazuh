# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from os import remove
from os.path import exists
from dataclasses import asdict
from typing import List, Optional

from wazuh.core.exception import WazuhError
from wazuh.core.engine import get_engine_client
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.engine.models.resources import ResourceFormat, Resource, Status, ResourceType
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.assets import save_asset_file, generate_asset_file_path
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array, full_copy, safe_move

DEFAULT_DECODER_FORMAT = ResourceFormat.JSON
ENGINE_USER_NAMESPACE = 'user'

def create_decoder(filename: str, contents: Resource, policy_type: PolicyType) -> AffectedItemsWazuhResult:
    """Create a new decoder resource.

    Parameters
    ----------
    filename : str
        The name of the decoder file.
    contents : Resource
        The decoder resource object.
    policy_type : PolicyType
        The policy type for the decoder.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object indicating success or failure.

    Raises
    ------
    WazuhError
        If the decoder file already exists (code 8001),
        if validation fails (code 8002),
        or if creation fails (code 8003).
    """
    result = AffectedItemsWazuhResult(all_msg='Decoder was successfully uploaded',
                                      none_msg='Could not upload decoder'
                                      )
    file_contents_json = json.dumps(asdict(contents))
    asset_file_path = generate_asset_file_path(filename, policy_type)
    try:
        if exists(asset_file_path):
            raise WazuhError(8001)

        # Create file
        save_asset_file(asset_file_path, file_contents_json)

        async with get_engine_client() as client:

            # Validate contents
            validation_results = client.catalog.validate_resource(
                name=contents.name,
                format=DEFAULT_DECODER_FORMAT,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE
            )

            validate_response_or_raise(validation_results, 8002)

            # Create the new resource
            creation_results = client.content.create_resource(
                type=ResourceType.DECODER,
                format=DEFAULT_DECODER_FORMAT,
                content=file_contents_json,
                policy_type=policy_type
            )

            validate_response_or_raise(creation_results, 8003)

        result.affected_items.append(filename)
        result.total_affected_items = len(result.affected_items)
    except WazuhError as exc:
        result.add_failed_item(id_=filename, error=exc)
    finally:
        exists(asset_file_path) and remove(asset_file_path)

    return result

def get_decoders(names: List[str], search: Optional[str], status: Optional[Status], policy_type: PolicyType) -> AffectedItemsWazuhResult:
    """Retrieve decoder resources.

    Parameters
    ----------
    names : List[str]
        List of decoder names to retrieve.
    search : Optional[str]
        Search text to filter decoders.
    status : Optional[Status]
        Status to filter decoders.
    policy_type : PolicyType
        The policy type for the decoders.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object containing the retrieved decoders.

    Raises
    ------
    WazuhError
        If decoder retrieval fails (code 8004).
    """
    results = AffectedItemsWazuhResult(none_msg='No decoder was returned',
                                      some_msg='Some decoders were not returned',
                                      all_msg='All selected decoders were returned')

    async with get_engine_client() as client:
        decoders_response = client.content.get_resources(
            type=ResourceType.DECODER,
            name_list=names,
            policy_type=policy_type
        )

        validate_response_or_raise(decoders_response, 8004)

        parsed_decoders = process_array(
            decoders_response['content'],
            search_text=search,
            filters={'status': status} if status else None
        )
        results.affected_items = parsed_decoders['items']
        results.total_affected_items = parsed_decoders['totalItems']

        return results

def update_decoder(filename: str, contents: Resource, policy_type: PolicyType):
    """Update an existing decoder resource.

    Parameters
    ----------
    filename : str
        The name of the decoder file.
    contents : Resource
        The decoder resource object.
    policy_type : PolicyType
        The policy type for the decoder.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object indicating success or failure.

    Raises
    ------
    WazuhError
        If the decoder file does not exist (code 8005),
        if backup copy fails (code 1019),
        if file deletion fails (code 1907),
        if validation fails (code 8002),
        or if update fails (code 8006).
    """
    result = AffectedItemsWazuhResult(all_msg='Decoder was successfully uploaded',
                                      none_msg='Could not upload decoder'
                                      )

    backup_file = ''
    asset_file_path = generate_asset_file_path(filename, policy_type)
    try:
        if not exists(asset_file_path):
            raise WazuhError(8005)

        # Creates a backup copy
        backup_file = f'{asset_file_path}.backup'
        try:
            full_copy(asset_file_path, backup_file)
        except IOError as exc:
            raise WazuhError(1019) from exc

        # Deletes the file
        try:
            remove(asset_file_path)
        except IOError as exc:
            raise WazuhError(1907) from exc

        # Uploads the new file contents
        file_contents_json =  json.dumps(asdict(contents))
        save_asset_file(asset_file_path, file_contents_json)

        # Upload to Engine
        async with get_engine_client() as client:
            # Validate contents
            validation_results = client.catalog.validate_resource(
                name=contents.name,
                format=DEFAULT_DECODER_FORMAT,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE
            )

            validate_response_or_raise(validation_results, 8002)

            # Update contents
            update_results = client.content.update_resource(
                name=contents.name,
                content=file_contents_json,
                policy_type=policy_type
            )

            validate_response_or_raise(update_results, 8006)

        result.affected_items.append(filename)
    except WazuhError as exc:
        result.add_failed_item(id_=filename, error=exc)
    finally:
        exists(backup_file) and safe_move(backup_file, asset_file_path)

    return result


def delete_decoders():
    pass