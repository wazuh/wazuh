# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import json
import os
import pytest

from wazuh.rbac.post_processor import list_handler


test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')
permissions = list()
results = list()
with open(test_data_path + 'RBAC_postprocessor.json') as f:
    input_output = [(config['result'],
                    config['original'],
                    config['allowed'],
                    config['target'],
                    config['add_denied'],
                    config['post_proc_kwargs'],
                    config['output']) for config in json.load(f)]


@pytest.mark.parametrize('result, original, allowed, target, add_denied, post_proc_kwargs, output', input_output)
def test_list_handler(result, original, allowed, target, add_denied, post_proc_kwargs, output):
    processed_input = list_handler(result, original, allowed, target, add_denied, **post_proc_kwargs)
    assert processed_input == output
