# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import os
from functools import lru_cache

import yaml

from api import __path__ as api_path
from api.constants import SECURITY_CONFIG_PATH
from wazuh import WazuhInternalError, WazuhError
from api import configuration


@lru_cache(maxsize=None)
def load_spec():
    with open(os.path.join(api_path[0], 'spec', 'spec.yaml'), 'r', encoding='utf-8') as stream:
        return yaml.safe_load(stream)


def update_security_conf(new_config):
    """Update dict and write it in the configuration file.

    Parameters
    ----------
    new_config : dict
        Dictionary with the new configuration.
    """
    configuration.security_conf.update(new_config)

    if new_config:
        try:
            with open(SECURITY_CONFIG_PATH, 'w+') as f:
                yaml.dump(configuration.security_conf, f)
        except IOError:
            raise WazuhInternalError(1005)
    else:
        raise WazuhError(4021)

