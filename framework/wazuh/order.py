from api.models.order_model import Orders
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["order:send"], resources=["*:*:*"], post_proc_func=None)
async def send_orders(orders: Orders) -> AffectedItemsWazuhResult:
    """Send orders to the local server and distribute them to other nodes and components.
    
    Parameters
    ----------
    orders : Orders
        Orders object holding a list of orders.

    Returns
    -------
    AffectedItemsWazuhResult
        Result with the orders sent.
    """
    result = AffectedItemsWazuhResult(
        all_msg="All orders were sent to the server",
        some_msg="Some orders were sent to the server",
        none_msg="No orders were sent to the server"
    )
    
    result.total_affected_items = len(result.affected_items)

    return result
