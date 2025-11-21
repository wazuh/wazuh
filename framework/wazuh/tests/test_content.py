#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest


with patch("wazuh.core.common.wazuh_uid"):
    with patch("wazuh.core.common.wazuh_gid"):
        sys.modules["wazuh.rbac.orm"] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules["wazuh.rbac.orm"]
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.content import update_content
        from wazuh.core.exception import WazuhError
        from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")


def test_update_content_ok():
    """Tests update content"""

    with patch(
        "wazuh.core.cluster.utils.update_content", return_value=WazuhResult({"message": "Update content request sent"})
    ):
        result = update_content()

    # Assert there are no errors and type of the result.
    assert isinstance(result, AffectedItemsWazuhResult), "No expected result type"
    assert result.render()["data"]["total_failed_items"] == 0


@pytest.mark.parametrize(
    "exception",
    [
        WazuhError(1901, "Socket path not exists"),
        WazuhError(1902, "Socket error"),
        WazuhError(1014, "Socket send error"),
    ],
)
@patch("wazuh.core.cluster.utils.update_content")
def test_restart_ko_socket(update_content_mock, exception):
    """Tests update content with exceptions"""

    update_content_mock.side_effect = exception
    result = update_content()

    assert isinstance(result, AffectedItemsWazuhResult), "No expected result type"
    assert result.message == "Could not send content update request to any node"
