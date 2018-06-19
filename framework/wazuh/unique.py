#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from glob import glob
from wazuh.database import Connection

def _get_unique(select_fields, table):
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])

    items = {}
    for user_field, user_db in select_fields.items():
        query = "SELECT DISTINCT {0} FROM {1}".format(user_db, table)
        conn.execute(query)
        items[user_field] = []
        for db_tuple in conn:
            if db_tuple[0] is None:
                continue
            items[user_field].append(db_tuple[0])

    return items


def _get_unique_items(select, valid_select_fields, table):
    if select:
        incorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields.keys()))
        if incorrect_fields:
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                format(', '.join(valid_select_fields.keys()), ','.join(incorrect_fields)))

        select_fields = {field:valid_select_fields[field] for field in select['fields'] if field in valid_select_fields.keys()}
    else:
        select_fields = valid_select_fields

    return _get_unique(select_fields, table)


def get_unique_agents(select=None):
    valid_select_fields = {'group': '`group`', 'node_name': 'node_name', 'version': 'version', 'os.platform': 'os_platform'}
    table = 'agent'
    return _get_unique_items(select, valid_select_fields, table)