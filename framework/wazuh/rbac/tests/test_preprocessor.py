# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os

import pytest
from wazuh.rbac.preprocessor import PreProcessor

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')

permissions = list()
results = list()
actual_test = 0
with open(test_data_path + 'RBAC_preprocessor_policies.json') as f:
    file = json.load(f)

inputs = [test_case['no_processed_policies'] for test_case in file]
outputs = [test_case['processed_policies'] for test_case in file]


@pytest.mark.parametrize('input_, output', zip(inputs, outputs))
def test_process_policy(db_setup, input_, output):
    """Validate that the `process_policy` method works as expected."""
    preprocessor = PreProcessor()
    for policy in input_:
        preprocessor.process_policy(policy)
    preprocessed_policies = preprocessor.get_optimize_dict()
    assert preprocessed_policies == output
