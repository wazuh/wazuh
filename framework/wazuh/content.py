# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.cluster.cluster import get_node
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.cluster import utils
from wazuh.rbac.decorators import expose_resources


node_id = get_node().get("node")

_update_content_default_result_kwargs = {
    "all_msg": "Content update request sent to all nodes",
    "some_msg": "Could not send content update request to some specified nodes",
    "none_msg": "Could not send content update request to any node",
    "sort_casting": ["str"],
}


@expose_resources(
    actions=["security:update"],
    resources=["*:*:*"],
    post_proc_kwargs={"default_result_kwargs": _update_content_default_result_kwargs},
)
def update_content() -> AffectedItemsWazuhResult:
    """Send the content update request to the engine and VD.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the content updateoperation, including affected and failed items.
    """
    results = AffectedItemsWazuhResult(**_update_content_default_result_kwargs)

    try:
        utils.update_content()
        results.affected_items.append(node_id)
    except WazuhError as e:
        results.add_failed_item(id_=node_id, error=e)

    results.total_affected_items = len(results.affected_items)
    return results
