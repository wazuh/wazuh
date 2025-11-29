import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

import wazuh.content as content
from api.controllers.util import json_response
from api.util import raise_if_exc
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger("wazuh-api")


async def put_content_update(pretty: bool = False) -> ConnexionResponse:
    """Send the content update order on all nodes in the cluster.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    nodes = raise_if_exc(await get_system_nodes())

    master_node = nodes.pop(0)

    dapi = DistributedAPI(
        f=content.update_content,
        request_type="distributed_master",
        is_async=False,
        wait_for_complete=True,
        logger=logger,
        broadcasting=True,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
        nodes=nodes,
    )
    result = raise_if_exc(await dapi.distribute_function())

    dapi_master = DistributedAPI(
        f=content.update_content,
        request_type="local_master",
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    master_result = raise_if_exc(await dapi_master.distribute_function())
    if master_result.total_affected_items > 0:
        result.affected_items.insert(0, master_node)
        result.total_affected_items += 1

    return json_response(result, pretty=pretty)
