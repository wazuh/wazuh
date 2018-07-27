#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from glob import glob
from wazuh.database import Connection
from wazuh.utils import get_fields_to_nest, plain_dict_to_nested_dict

def _get_response_from_conn(conn, dict_name_fields=None):
    if not dict_name_fields:
        response = [item for db_tuple in conn for item in db_tuple if item]
    else:
        response = [{field: value for field, value in zip(dict_name_fields, db_tuple)}
                    for db_tuple in conn]

    return response


def _db_request(query, request={}):
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])
    conn.execute(query, request)

    return conn


def _get_total_items(query, request):
    count_query = "SELECT COUNT(*) FROM ({})".format(query)
    total_items = _db_request(count_query.format(query), request).fetch()[0]
    return total_items


def _nest_dictionary_by_keys(fields, dict, keys):
    fields_to_nest, non_nested = get_fields_to_nest(fields.values(), keys, '.')
    return [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, keys, '.') for d in dict]


def _get_group_distinct(select_fields, table, offset=0, limit=common.database_limit, sort={}, search={}, count=True):
    query = "SELECT DISTINCT {} FROM {}"
    db_fields = ','.join(select_fields.values())
    request = {}

    # Search
    if search:
        query += " WHERE"
        query += " NOT" if bool(search['negation']) else ''
        query += " (" + " OR ".join(x + ' LIKE :search' for x in select_fields.values()) + " )"
        request['search'] = '%{0}%'.format(int(search['value']) if search['value'].isdigit()
                                                                    else search['value'])

    total_items = _get_total_items(query.format(db_fields, table), request)

    if sort:
        query += ' ORDER BY {} {}'.format(','.join(sort['fields']), sort['order'])

    query += " LIMIT :offset,:limit"
    request.update({'offset': offset, 'limit':limit})

    conn = _db_request(query.format(db_fields, table), request)
    items = _get_response_from_conn(conn, select_fields)

    if count:
        for item in items:
            count_query = "SELECT COUNT(*) FROM {} WHERE ".format(table)
            count_query_fields = []
            for field, value in item.items():
                if value:
                    count_query_fields.append("{}='{}'".format(select_fields[field], value))
                else:
                    count_query_fields.append("{} IS NULL".format(select_fields[field]))

            count_query += " AND ".join(count_query_fields)
            item['count'] = _db_request(count_query).fetch()[0] if count_query_fields else 0

    return items, total_items


def _get_distinct_items(valid_select_fields, table, select={}, offset=0, limit=common.database_limit,
                        search={}, sort={}, nest=[], filter_fields={}):
    offset = int(offset)
    limit = int(limit)
    if limit:
        if limit > common.maximum_database_limit:
            raise WazuhException(1405, str(limit))
    elif limit == 0:
        raise WazuhException(1406)

    if select:
        incorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields.keys()))
        if incorrect_fields:
            raise WazuhException(1724, "Allowed fields: {0}. Fields {1}".\
                format(', '.join(valid_select_fields.keys()), ','.join(incorrect_fields)))

        select_fields = {field:valid_select_fields[field] for field in select['fields'] if field in valid_select_fields.keys()}
    else:
        select_fields = valid_select_fields

    if filter_fields:
        incorrect_fields = map(lambda x: str(x), set(filter_fields['fields']) - set(valid_select_fields.keys()))
        if incorrect_fields:
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                format(', '.join(valid_select_fields.keys()), ','.join(incorrect_fields)))

    if sort:
        if not set(sort.get('fields')).issubset(select_fields.keys()):
            raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(valid_select_fields.keys(), sort['fields']))
        sort['fields'] = [valid_select_fields[field] for field in sort['fields'] if field in valid_select_fields.keys()]

    items, total_items = _get_group_distinct(select_fields=select_fields, table=table, offset=offset,
                                             limit=limit, sort=sort, search=search)

    if filter_fields:
        items = [{key:value for key,value in item.items() if key in filter_fields['fields']} for item in items]

    if nest:
        items = _nest_dictionary_by_keys(select_fields, items, nest)


    return {'items': items, 'totalItems': total_items}


def get_distinct_agents(offset=0, limit=common.database_limit, db_select={}, search={}, sort={}, filter_fields={}):
    valid_select_fields = {'group': '`group`', 'node_name': 'node_name', 'version': 'version',
                           'manager_host': 'manager_host', 'os.codename': 'os_codename',
                           'os.major': 'os_major', 'os.minor': 'os_minor', 'os.uname': 'os_uname',
                           'os.arch': 'os_arch', 'os.build':'os_build','os.name': 'os_name',
                           'os.version': 'os_version', 'os.platform': 'os_platform'}
    table = 'agent'

    return _get_distinct_items(table=table, valid_select_fields=valid_select_fields,
                                 offset=offset, limit=limit, select=db_select,
                                 search=search, sort=sort, nest=['os'], filter_fields=filter_fields)