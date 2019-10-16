# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import json
import os
import pytest
from wazuh.rbac.preprocessor import optimize_resources


test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')
permissions = list()
results = list()
actual_test = 0
with open(test_data_path + 'RBAC_preprocessor_policies.json') as f:
    file = json.load(f)

inputs = [test_case['no_processed_policies'] for test_case in file]
outputs = [test_case['processed_policies'] for test_case in file]


@pytest.mark.parametrize('input, output', zip(inputs, outputs))
def test_expose_resources(input, output):

    with patch('wazuh.rbac.preprocessor.RBAChecker.run', return_value=input):
        preprocessed_policies = optimize_resources()
        assert (preprocessed_policies == output)
