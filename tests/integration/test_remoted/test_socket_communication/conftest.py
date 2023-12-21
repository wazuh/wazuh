"""
 Copyright (C) 2015-2023, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from wazuh_testing.utils import services


@pytest.fixture
def protocols_list_to_str_upper_case(request, test_metadata):
    """convert valid_protocol list to comma separated uppercase string

        parameters: test_metadata
        Returns:
        protocol_string_upper: string protocols in uppercase
    """
    protocol_array = []
    protocol_string_upper = []
    for I in test_metadata['valid_protocol'] :
        protocol_array.append(I)
        protocol_array.sort()

    if len(test_metadata['valid_protocol']) > 0 :
        protocol_string = protocol_array[0]
        protocol_string_upper = protocol_string.upper();

    if len(protocol_array) > 1:
        protocol_string = protocol_array[0] + ',' + protocol_array[1]
        protocol_string_upper = protocol_string.upper();

    return protocol_string_upper
