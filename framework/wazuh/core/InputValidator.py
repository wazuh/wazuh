# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import operator
import re
from functools import reduce

from api.validator import _group_names


class InputValidator:
    """
    Class to do Input Validation.
    """

    def check_name(self, name: str, regex_str: str = r"\w+") -> bool:
        """Abstract function to check a name matches a regex (\\w+ by default).

        Parameters
        ----------
        name : str
            Name to check.
        regex_str : str
            Regular expression to do the matching. Default: r"\\w+"

        Returns
        -------
        bool
            True if it matched, False otherwise.
        """
        regex = re.compile(regex_str)
        matching = regex.match(name)
        if matching:
            return matching.group() == name
        else:
            return False

    def check_length(self, name: str, length: int = 255, func: callable = operator.le) -> bool:
        """Function to compare the length of a string.

        Parameters
        ----------
        name : str
            String to check.
        length : int
            Length used to do the comparison. By default, 255.
        func : callable
            Operator to do the comparison with. By default, <.

        Returns
        -------
        bool
            True or False.
        """
        return func(len(name), length)

    def group(self, group_name: str) -> bool:
        """Function to validate the name of a group.

        Parameters
        ----------
        group_name : str
            Name of the group to be validated.

        Returns
        -------
        bool
            True if the input name is valid and False otherwise.
        """

        def check_single_group_name(group_name: str) -> bool:
            return self.check_length(group_name) and self.check_name(group_name, regex_str=_group_names)

        if isinstance(group_name, list):
            return reduce(operator.mul, map(lambda x: check_single_group_name(x), group_name))
        else:
            return check_single_group_name(group_name)
