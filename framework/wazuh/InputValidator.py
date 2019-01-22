#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import operator
from functools import reduce


class InputValidator:
    """
    Class to do Input Validation
    """

    def check_name(self, name, regex_str=r"\w+"):
        """
        Abstract function to check a name matches a regex (\w+ by default)
        :param name: Name to check
        :param regex_str: Regular expression to do the matching
        :return: True if it matched, False otherwise.
        """
        regex = re.compile(regex_str)
        matching = regex.match(name)
        if matching:
            return matching.group() == name
        else: 
            return False


    def check_length(self, name, length=255, func=operator.le):
        """
        Function to compare the length of a string.
        :param name: String to check.
        :param length: Length used to do the comparison. By default, 255.
        :param func: Operator to do the comparison with. By default, <.
        :return: True or False.
        """
        return func(len(name), length)


    def group(self, group_name):
        """
        function to validate the name of a group. Returns True if the
        input name is valid and False otherwise

        group_name: name of the group to be validated
        """
        def check_single_group_name(group_name):
            return self.check_length(group_name) and self.check_name(group_name, regex_str=r'[A-Za-z0-9.\-_]+')

        if isinstance(group_name, list):
            return reduce(operator.mul, map(lambda x: check_single_group_name(x), group_name))
        else:
            return check_single_group_name(group_name)
