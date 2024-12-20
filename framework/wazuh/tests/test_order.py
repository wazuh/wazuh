# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import MagicMock, patch

import pytest
from wazuh.core.exception import WazuhClusterError

from api.models.order_model import Order

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.order import send_orders


@pytest.mark.parametrize(
    'side_effect,message',
    [
        (None, 'All orders were published'),
        (WazuhClusterError(3023), 'No orders were published'),
    ],
)
@patch('wazuh.order.distribute_orders')
@patch('wazuh.order.local_client.LocalClient')
async def test_send_orders(local_client_mock, distribute_orders_mock, side_effect, message):
    """Validate that the `send_orders` function is working as expected."""
    distribute_orders_mock.side_effect = side_effect
    orders = [Order().to_dict()]
    result = await send_orders(orders=orders)

    assert result.message == message
    assert result.total_affected_items == 0 if side_effect else len(orders)
