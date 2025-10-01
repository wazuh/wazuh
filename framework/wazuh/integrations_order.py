import json
from dataclasses import asdict
from os import remove
from os.path import exists

from wazuh import WazuhError
from wazuh.core.assets import generate_asset_file_path, save_asset_file
from wazuh.core.engine import get_engine_client
from wazuh.core.engine.models.integrations_order import IntegrationsOrder
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import full_copy, safe_move

DEFAULT_INTEGRATIONS_ORDER_FILENAME = 'integrations_order'
DEFAULT_USER_NAMESPACE = 'user'

def create_integrations_order(order: IntegrationsOrder, policy_type: PolicyType) -> AffectedItemsWazuhResult:
    """Create a new integrations order resource.

    Parameters
    ----------
    order : IntegrationsOrder
        The integrations order object to be created.
    policy_type : PolicyType
        The policy type for the integrations order.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object with affected or failed items.

    Raises
    ------
    WazuhError
        If the file already exists or engine validation fails (codes: 8009, 8011).
    """
    result = AffectedItemsWazuhResult(all_msg='Integrations order was successfully uploaded',
                                      none_msg='Could not upload Integration order')

    file_contents_json = json.dumps(asdict(order))
    integration_order_path_file = generate_asset_file_path(DEFAULT_INTEGRATIONS_ORDER_FILENAME, policy_type)

    try:
        if exists(integration_order_path_file):
            raise WazuhError(8009)

        # Create file
        save_asset_file(integration_order_path_file, file_contents_json)

        async with get_engine_client() as client:
            creation_results = client.integrations_order.create_order(
                content=file_contents_json,
                policy_type=policy_type
            )

            validate_response_or_raise(creation_results, 8011)

        result.affected_items.append(DEFAULT_INTEGRATIONS_ORDER_FILENAME)
        result.total_affected_items = len(result.affected_items)
    except WazuhError as exc:
        result.add_failed_item(id_=DEFAULT_INTEGRATIONS_ORDER_FILENAME, error=exc)
    finally:
        exists(integration_order_path_file) and remove(integration_order_path_file)

    return result

def get_integrations_order(policy_type: PolicyType) -> AffectedItemsWazuhResult:
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
        If retrieval or validation fails (code: 8011).
    """
    results = AffectedItemsWazuhResult(none_msg='No integrations order was returned',
                                      some_msg='Some integrations order were not returned',
                                      all_msg='All selected integrations order were returned')

    async with get_engine_client() as client:
        integrations_order_response = client.integrations_order.get_order(policy_type=policy_type)

        validate_response_or_raise(integrations_order_response, 8011)

        results.affected_items = integrations_order_response['content']
        results.total_affected_items = len(integrations_order_response['content'])

    return results

def delete_integrations_order(policy_type: PolicyType) -> AffectedItemsWazuhResult:
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
        If the file does not exist or file/engine operations fail (codes: 8010, 1019, 1907, 8012).
    """
    result = AffectedItemsWazuhResult(all_msg='Integrations order file was successfully deleted',
                                      some_msg='Some integrations order were not returned',
                                      none_msg='Could not delete integrations order file')

    backup_file = ''
    integration_order_path_file = generate_asset_file_path(DEFAULT_INTEGRATIONS_ORDER_FILENAME, policy_type)

    try:
        if not exists(integration_order_path_file):
            raise WazuhError(8010)

        # Creates a backup copy
        backup_file = f'{integration_order_path_file}.backup'
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
            delete_results = client.integrations_order.delete_order(
                policy_type=policy_type
            )

            validate_response_or_raise(delete_results, 8012)
    except WazuhError as exc:
        result.add_failed_item(id_=DEFAULT_INTEGRATIONS_ORDER_FILENAME, error=exc)
    finally:
        exists(backup_file) and safe_move(backup_file, integration_order_path_file)

    result.total_affected_items = len(result.affected_items)
    return result
