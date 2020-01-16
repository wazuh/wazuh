#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock
from wazuh.common import database_limit
import wazuh.core.sca

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..', '..', 'api'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.exception import WazuhError
        from wazuh.core import sca


fields_translation = {**sca.fields_translation_sca_check,
                      **sca.fields_translation_sca_check_compliance,
                      **sca.fields_translation_sca_check_rule}
full_select = (list(sca.fields_translation_sca_check.keys()) +
               list(sca.fields_translation_sca_check_compliance.keys()) +
               list(sca.fields_translation_sca_check_rule.keys())
               )


# Tests

@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data, default_sort_field, '
                         'filters, fields, default_query, count_field', [
    (['000'], 0, database_limit, None, None, None, True, True,
     f"policy_id={policy_id}" if q == "" else f"policy_id={policy_id};{q}")
])
@patch('wazuh.common.ossec_path', new='wazuh/core/tests/data')
def test_WazuhDBQuerySCA(expected_exception, command, arguments, custom):
    """

    Parameters
    ----------
    expected_exception
    command
    arguments
    custom

    Returns
    -------

    """
    db_query = sca.WazuhDBQuerySCA(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                   select=full_select, count=True, get_data=True,
                                   query=f"policy_id={policy_id}" if q == "" else f"policy_id={policy_id};{q}",
                                   filters=filters, default_query=default_query_sca_check,
                                   default_sort_field='policy_id', fields=fields_translation, count_field='id')
