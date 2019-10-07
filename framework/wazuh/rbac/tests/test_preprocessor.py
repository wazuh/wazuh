# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import json
import os

from wazuh.rbac.pre_policies import optimize_resources


test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')
permissions = list()
results = list()
actual_test = 0
with open(test_data_path + 'RBAC_preprocessor_policies.json') as f:
    tests_cases = [test_case for test_case in json.load(f)]


def test_expose_resources():

    def mock_run():
        global actual_test
        actual_test += 1
        return tests_cases[actual_test - 1]['no_processed_policies']

    with patch('wazuh.rbac.pre_policies.RBAChecker.run', side_effect=mock_run):
        for index, test_case in enumerate(tests_cases):
            preprocessed_policies = optimize_resources()
            assert (preprocessed_policies == tests_cases[index]['processed_policies'])
