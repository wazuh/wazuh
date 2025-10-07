# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from os import remove
from os.path import exists
from dataclasses import asdict
from typing import Optional, List

from wazuh import WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.assets import generate_integrations_file_path, save_asset_file, generate_asset_filename
from wazuh.core.engine import get_engine_client
from wazuh.core.engine.models.integration import Integration
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, Status
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array, full_copy, safe_move

DEFAULT_INTEGRATION_FORMAT = 'json'
ENGINE_USER_NAMESPACE = 'user'

@expose_resources(actions=['integrations:create'], resources=["*:*:*"])
async def create_integration(integration: Integration, policy_type: PolicyType) -> AffectedItemsWazuhResult:
    """Create a new integration resource.

    Parameters
    ----------
    integration : Integration
        The integration object to be created.
    policy_type : PolicyType
        The policy type for the integration.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If file operations or engine validation fail (codes: 8002, 8003).
    """
    result = AffectedItemsWazuhResult(all_msg='Integration was successfully uploaded',
                                      none_msg='Could not upload Integration'
                                      )

    filename = generate_asset_filename(integration.id)
    file_contents_json = json.dumps(asdict(integration))
    integration_path_file = generate_integrations_file_path(filename, policy_type)


    try:
        # Create file
        save_asset_file(integration_path_file, file_contents_json)

        async with get_engine_client() as client:

            # Validate contents
            validation_results = client.catalog.validate_resource(
                name=integration.name,
                format=DEFAULT_INTEGRATION_FORMAT,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE
            )

            validate_response_or_raise(validation_results, 8002)

            # Create the new integration
            creation_results = client.content.create_resource(
                type=ResourceType.INTEGRATION,
                format=DEFAULT_INTEGRATION_FORMAT,
                content=file_contents_json,
                policy_type=policy_type
            )

            validate_response_or_raise(creation_results, 8003)

        result.affected_items.append(filename)
        result.total_affected_items = len(result.affected_items)
    except WazuhError as exc:
        result.add_failed_item(id_=filename, error=exc)
    finally:
        exists(integration_path_file) and remove(integration_path_file)

    return result

@expose_resources(actions=['integrations:read'], resources=["*:*:*"])
async def get_integrations(names: str, search: Optional[str], status: Optional[Status], policy_type:PolicyType) -> AffectedItemsWazuhResult:
    """Retrieve integration resources.

    Parameters
    ----------
    names : str
        Names of the integrations to retrieve.
    search : Optional[str]
        Search string to filter integrations.
    status : Optional[Status]
        Status to filter integrations.
    policy_type : PolicyType
        The policy type for the integrations.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If retrieval or validation fails (code: 8007).
    """
    results = AffectedItemsWazuhResult(none_msg='No integration was returned',
                                      some_msg='Some integrations were not returned',
                                      all_msg='All selected integrations were returned')

    async with get_engine_client() as client:
        integrations_response = client.content.get_resources(
            type=ResourceType.INTEGRATION,
            name_list=names,
            policy_type=policy_type
        )

        validate_response_or_raise(integrations_response, 8007)

        parsed_decoders = process_array(
            integrations_response['content'],
            search_text=search,
            filters={'status': status} if status else None
        )
        results.affected_items = parsed_decoders['items']
        results.total_affected_items = parsed_decoders['totalItems']

        return results

@expose_resources(actions=['integrations:update'], resources=["*:*:*"])
async def update_integration(integration: Integration, policy_type: PolicyType):
    """Update an existing integration resource.

    Parameters
    ----------
    integration : Integration
        The updated integration object.
    policy_type : PolicyType
        The policy type for the integration.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If the integration does not exist or file/engine operations fail (codes: 8005, 1019, 1907, 8002, 8008).
    """
    result = AffectedItemsWazuhResult(all_msg='Integration was successfully uploaded',
                                      none_msg='Could not upload integration'
                                      )

    backup_file = ''
    filename = generate_asset_filename(integration.id)
    integration_file_path = generate_integrations_file_path(filename, policy_type)
    try:
        if not exists(integration_file_path):
            raise WazuhError(8005)

        # Creates a backup copy
        backup_file = f'{integration_file_path}.backup'
        try:
            full_copy(integration_file_path, backup_file)
        except IOError as exc:
            raise WazuhError(1019) from exc

        # Deletes the file
        try:
            remove(integration_file_path)
        except IOError as exc:
            raise WazuhError(1907) from exc

        # Uploads the new file contents
        file_contents_json =  json.dumps(asdict(integration))
        save_asset_file(integration_file_path, file_contents_json)

        # Upload to Engine
        async with get_engine_client() as client:
            # Validate contents
            validation_results = client.catalog.validate_resource(
                name=integration.name,
                format=DEFAULT_INTEGRATION_FORMAT,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE
            )

            validate_response_or_raise(validation_results, 8002)

            # Update contents
            update_results = client.content.update_resource(
                name=integration.name,
                content=file_contents_json,
                policy_type=policy_type
            )

            validate_response_or_raise(update_results, 8008)

        result.affected_items.append(filename)
    except WazuhError as exc:
        result.add_failed_item(id_=filename, error=exc)
    finally:
        exists(backup_file) and safe_move(backup_file, integration_file_path)

    result.total_affected_items = len(result.affected_items)
    return result

@expose_resources(actions=['integrations:delete'], resources=["*:*:*"])
async def delete_integration(names: List[str], policy_type: PolicyType):
    """Delete one or more integration resources.

    Parameters
    ----------
    names : List[str]
        List of integration names to delete.
    policy_type : PolicyType
        The policy type for the integrations.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If the integration does not exist or file/engine operations fail (codes: 8005, 1019, 1907, 8007).
    """
    result = AffectedItemsWazuhResult(all_msg='Integration file was successfully deleted',
                                      some_msg='Some integrations were not returned',
                                      none_msg='Could not delete integration file')

    for name in names:
        backup_file = ''
        integration_file_path = generate_integrations_file_path(name, policy_type)

        try:
            if not exists(integration_file_path):
                raise WazuhError(8005)

            # Creates a backup copy
            backup_file = f'{integration_file_path}.backup'
            try:
                full_copy(integration_file_path, backup_file)
            except IOError as exc:
                raise WazuhError(1019) from exc

            # Deletes the file
            try:
                remove(integration_file_path)
            except IOError as exc:
                raise WazuhError(1907) from exc

            # Delete asset
            async with get_engine_client() as client:
                delete_results = client.content.delete_resource(
                    name=name,
                    policy_type=policy_type
                )

                validate_response_or_raise(delete_results, 8007)

            result.affected_items.append(name)
        except WazuhError as exc:
            result.add_failed_item(id_=name, error=exc)
        finally:
            exists(backup_file) and safe_move(backup_file, integration_file_path)

    result.total_affected_items = len(result.affected_items)
    return result
