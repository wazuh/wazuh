# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from enum import Enum


class EngineCommand(Enum):
    """Base class for engine commands."""
    pass


class MetricCommand(EngineCommand):
    """Enum class representing metric commands."""
    DUMP = 'metrics.metrics/get'
    ENABLE = 'metrics.metrics/enable'
    LIST = 'metrics.metrics/list'
    GET = 'metrics.metrics/get'
    TEST = 'metrics.metrics/test'


