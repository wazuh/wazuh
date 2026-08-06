# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify
# it under the terms of GPLv2

from enum import Enum


class IndexerKey(str, Enum):
    """Opensearch API request fields keys."""

    _INDEX = "_index"
    _ID = "_id"
    _SOURCE = "_source"
    _DOCUMENTS = "_documents"
    ID = "id"
    DOC = "doc"
    MATCH = "match"
    MATCH_ALL = "match_all"
    QUERY = "query"
    QUERY_STRING = "query_string"
    CREATE = "create"
    DELETE = "delete"
    INDEX = "index"
    UPDATE = "update"
    BOOL = "bool"
    MUST = "must"
    HITS = "hits"
    TOTAL = "total"
    DELETED = "deleted"
    FAILURES = "failures"
    WILDCARD = "wildcard"
    BODY = "body"
    TERMS = "terms"
    TERM = "term"
    CONFLICTS = "conflicts"
    ITEMS = "items"
    IDS = "ids"
    PAINLESS = "painless"
    RANGE = "range"
    LTE = "lte"
    NOW = "now"
    FILTER = "filter"
    RESULT = "result"
    STATUS = "status"
    ERROR = "error"
    REASON = "reason"
