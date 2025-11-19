# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')


@expose_resources(actions=["asset:read"], resources=["content:space:{space}"])
def get_asset(space: str = None, asset_uuid: str = None) -> AffectedItemsWazuhResult:
    """Get asset from content space.

    Parameters
    ----------
    space : str
        Content space name.
    asset_uuid : str
        Asset UUID.

    Returns
    -------
    AffectedItemsWazuhResult
        Asset information.
    """
    pass


@expose_resources(actions=["asset:delete"], resources=["content:space:{space}"])
def delete_asset(space: str = None, asset_uuid: str = None) -> AffectedItemsWazuhResult:
    """Delete asset from content space.

    Parameters
    ----------
    space : str
        Content space name.
    asset_uuid : str
        Asset UUID.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    pass

@expose_resources(actions=["asset:create", "asset:update"], resources=["content:space:{space}"])
def upsert_asset(space: str = None, asset_data: str = None) -> AffectedItemsWazuhResult:
    """Create or update an asset in the content space.

    Parameters
    ----------
    space : str
        Content space name.
    asset_data : str
        Asset data.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    pass

@expose_resources(actions=["asset:read"], resources=["content:space:{space}"])
def get_integration_order(space: str = None) -> AffectedItemsWazuhResult:
    """Get the order of integration in the content space.

    Parameters
    ----------
    space : str
        Content space name.

    Returns
    -------

    """
    pass


@expose_resources(actions=["asset:update"], resources=["content:space:{space}"])
def update_integration_order(space: str = None, asset_data: str = None) -> AffectedItemsWazuhResult:
    """Update the order of integration in the content space.

    Parameters
    ----------
    space : str
        Content space name.
    asset_data : str
        New integration order data.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    pass


@expose_resources(actions=["asset:read"], resources=["content:space:{space}"])
def get_catalog(space: str = None, asset_type: str = None) -> AffectedItemsWazuhResult:
    """Get the catalog of assets in the content space.

    Parameters
    ----------
    space : str
        Content space name.
    asset_type : str
        Type of assets to retrieve.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    pass