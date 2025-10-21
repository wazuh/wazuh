# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from dataclasses import asdict
from os import remove
from os.path import exists

from wazuh import WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.assets import save_asset_file, generate_asset_file_path
from wazuh.core.engine import get_engine_client
from wazuh.core.engine.models.integrations_order import IntegrationsOrder
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import full_copy, safe_move

DEFAULT_INTEGRATIONS_ORDER_FILENAME = "integrations_order"
DEFAULT_USER_NAMESPACE = "user"


@expose_resources(actions=["integrations:create", "integrations:update"], resources=["*:*:*"])
async def upsert_integrations_order(order: IntegrationsOrder, policy_type: str) -> AffectedItemsWazuhResult:
    """Create or update an integrations order resource.

    This function will create a new integrations order if it does not exist,
    or update the existing one if found.

    Parameters
    ----------
    order : IntegrationsOrder
        The integrations order object to be created or updated.
    policy_type : PolicyType
        The policy type for the integrations order.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If engine validation fails or file operations fail.
    """
    filename = DEFAULT_INTEGRATIONS_ORDER_FILENAME
    asset_file_path = generate_asset_file_path(filename, PolicyType(policy_type), ResourceType.INTEGRATIONS_ORDER)
    backup_file = None
    mode = None
    result = AffectedItemsWazuhResult(none_msg="Could not upload integrations order")

    file_contents_json = json.dumps(asdict(order))

    try:
        # Determine operation mode
        mode = "create" if not exists(asset_file_path) else "update"
        result.all_msg = f"Integrations order was successfully {mode}d"

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

        # Write new integrations order content
        save_asset_file(asset_file_path, file_contents_json)

        # Validate and push to engine
        async with get_engine_client() as client:
            if mode == "create":
                creation_results = await client.integrations_order.create_order(
                    content=asdict(order), policy_type=policy_type
                )
                validate_response_or_raise(creation_results, 9004, ResourceType.INTEGRATIONS_ORDER)
            else:
                update_results = await client.integrations_order.update_order(
                    content=asdict(order), policy_type=policy_type
                )
                validate_response_or_raise(update_results, 9005, ResourceType.INTEGRATIONS_ORDER)

        result.affected_items.append(filename)

    except WazuhError as exc:
        # Restore backup if it exists
        if backup_file and exists(backup_file):
            safe_move(backup_file, asset_file_path)
        elif mode == "create" and exists(asset_file_path):
            remove(asset_file_path)
        result.add_failed_item(id_=filename, error=exc)

    finally:
        # Cleanup leftover backup
        if backup_file and exists(backup_file):
            remove(backup_file)

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=["integrations:read"], resources=["*:*:*"])
async def get_integrations_order(policy_type: str) -> AffectedItemsWazuhResult:
    """Retrieve the integrations order resource.

    Parameters
    ----------
    policy_type : PolicyType
        The policy type for the integrations order.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If retrieval or validation fails (code: 9003).
    """
    results = AffectedItemsWazuhResult(
        none_msg="No integrations order was returned",
        some_msg="Some integrations order were not returned",
        all_msg="All selected integrations order were returned",
    )

    async with get_engine_client() as client:
        integrations_order_response = await client.integrations_order.get_order(policy_type=policy_type)

        validate_response_or_raise(integrations_order_response, 9003, ResourceType.INTEGRATIONS_ORDER)

        results.affected_items.append(integrations_order_response["content"])
        results.total_affected_items = len(results.affected_items)

    return results


@expose_resources(actions=["integrations:delete"], resources=["*:*:*"])
async def delete_integrations_order(policy_type: str) -> AffectedItemsWazuhResult:
    """Delete the integrations order resource.

    Parameters
    ----------
    policy_type : PolicyType
        The policy type for the integrations order.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If the file does not exist or file/engine operations fail (codes: 9006, 1019, 1907).
    """
    result = AffectedItemsWazuhResult(
        all_msg="Integrations order file was successfully deleted",
        some_msg="Some integrations order were not returned",
        none_msg="Could not delete integrations order file",
    )

    backup_file = ""
    integration_order_path_file = generate_asset_file_path(
        DEFAULT_INTEGRATIONS_ORDER_FILENAME, PolicyType(policy_type), ResourceType.INTEGRATIONS_ORDER
    )

    try:
        if not exists(integration_order_path_file):
            raise WazuhError(9006)

        # Creates a backup copy
        backup_file = f"{integration_order_path_file}.bak"
        try:
            full_copy(integration_order_path_file, backup_file)
        except IOError as exc:
            raise WazuhError(1019) from exc

        # Deletes the file
        try:
            remove(integration_order_path_file)
        except IOError as exc:
            raise WazuhError(1907) from exc

        # Delete integrations order
        async with get_engine_client() as client:
            delete_results = await client.integrations_order.delete_order(policy_type=policy_type)

            validate_response_or_raise(delete_results, 9006, ResourceType.INTEGRATIONS_ORDER)

        result.affected_items.append(DEFAULT_INTEGRATIONS_ORDER_FILENAME)
    except WazuhError as exc:
        if backup_file and exists(backup_file):
            safe_move(backup_file, integration_order_path_file)
        result.add_failed_item(id_=DEFAULT_INTEGRATIONS_ORDER_FILENAME, error=exc)
    else:
        if backup_file and exists(backup_file):
            remove(backup_file)

    result.total_affected_items = len(result.affected_items)
    return result
