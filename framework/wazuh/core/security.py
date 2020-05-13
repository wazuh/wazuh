# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import os
from functools import lru_cache

import yaml

from api import __path__ as api_path


@lru_cache(maxsize=None)
def load_spec():
    with open(os.path.join(api_path[0], 'spec', 'spec.yaml'), 'r', encoding='utf-8') as stream:
        return yaml.safe_load(stream)
