#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

class InputValidator:
    """
    Class to do Input Validation
    """

    def check_name(self, name, regex_str="\w+"):
        regex = re.compile(regex_str)
        matching = regex.match(name)
        if matching:
            return matching.group() == name
        else: 
            return False

    def check_length(self, name, length=100):
        return len(name) < length

    def group(self, group_name):
        """
        function to validate the name of a group. Returns True if the
        input name is valid and False otherwise

        group_name: name of the group to be validated
        """
        return self.check_length(group_name) and self.check_name(group_name)
