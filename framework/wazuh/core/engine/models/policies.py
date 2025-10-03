# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from enum import Enum

class PolicyType(str, Enum):
    """Enumeration for policy types used in asset management."""
    TESTING = 'testing'
    PRODUCTION = 'production'

    def dirname(self) -> str:
        """Return the directory name corresponding to the policy type."""
        mapping = {
            self.TESTING: 'testing',
            self.PRODUCTION: 'production'
        }
        return mapping.get(self)
