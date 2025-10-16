# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from enum import Enum

from wazuh.core.common import USER_TESTING_ASSETS_PATH, USER_PRODUCTION_ASSETS_PATH
from wazuh.core.exception import WazuhError

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

    def get_base_path(self):
        """Get the base path for the given policy type.

        Returns
        -------
        str
            The base path for the policy type.

        Raises
        ------
        WazuhError
            If the policy type is invalid (code 8000).
        """
        if self == PolicyType.TESTING:
            return USER_TESTING_ASSETS_PATH
        elif self == PolicyType.PRODUCTION:
            return USER_PRODUCTION_ASSETS_PATH
        else:
            raise WazuhError(8000, extra_message={'policy_type': self})
