# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from enum import Enum


class EngineCommand(Enum):
    """Base class for engine commands."""
    pass


class MetricCommand(EngineCommand):
    """Enum class representing metric commands."""
    DUMP = 'metrics.manager/dump'
    ENABLE = 'metrics.manager/enable'
    LIST = 'metrics.manager/list'
    GET = 'metrics.manager/get'
    TEST = 'metrics.manager/test'


class CatalogCommand(EngineCommand):
    """Enum class representing catalog commands."""
    POST = 'catalog.resource/post'
    GET = 'catalog.resource/get'
    PUT = 'catalog.resource/put'
    DELETE = 'catalog.resource/delete'
    VALIDATE = 'catalog.resource/validate'


class ConfigCommand(EngineCommand):
    """Enum class representing config commands."""
    GET = 'config.runtime/get'
    PUT = 'config.runtime/put'
    SAVE = 'config.runtime/save'


class IntegrationCommand(EngineCommand):
    """Enum class representing integration commands."""
    ADD_TO = 'integration.policy/add_to'
    REMOVE_FROM = 'integration.policy/remove_from'


class KvdbDBCommand(EngineCommand):
    """Enum class representing KVDB DB commands."""
    GET = 'kvdb.db/get'
    DELETE = 'kvdb.db/delete'
    PUT = 'kvdb.db/put'


class KvdbManagerCommand(EngineCommand):
    """Enum class representing KVDB Manager commands."""
    GET = 'kvdb.manager/get'
    POST = 'kvdb.manager/post'
    DELETE = 'kvdb.manager/delete'
    DUMP = 'kvdb.manager/dump'


class RouterCommand(EngineCommand):
    """Enum class representing router commands."""
    GET = 'router.route/get'
    POST = 'router.route/post'
    PATCH = 'router.route/patch'
    DELETE = 'router.route/delete'
    GET_TABLE = 'router.table/get'
    POST_QUEUE = 'router.queue/post'
