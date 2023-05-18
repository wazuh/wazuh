import sys

from collections import defaultdict


class GlobalParameters:
    """Class to allocate all global parameters for testing"""

    def __init__(self):
        timeouts = defaultdict(lambda: 10)
        timeouts['linux'] = 5
        timeouts['darwin'] = 5
        self._default_timeout = timeouts[sys.platform]
        self._fim_database_memory = False

    @property
    def default_timeout(self):
        """Getter method for the default timeout property

        Returns:
            int: representing the default timeout in seconds
        """
        return self._default_timeout

    @default_timeout.setter
    def default_timeout(self, value):
        """Setter method for the default timeout property

        Args:
            value (int): New value for the default timeout. Must be in seconds.
        """
        self._default_timeout = value

    @property
    def current_configuration(self):
        """Getter method for the current configuration property

        Returns:
            dict: A dictionary containing the current configuration.
        """
        return self._current_configuration

    @current_configuration.setter
    def current_configuration(self, value):
        """Setter method for the current configuration property

        Args:
            value (dict): New value for the current configuration.
        """
        self._current_configuration = value

    @property
    def fim_database_memory(self):
        """Getter method for the `fim_database_memory` property

        Returns:
            bool: representing if `fim_database_memory` is activated
        """
        return self._fim_database_memory

    @fim_database_memory.setter
    def fim_database_memory(self, value):
        """Setter method for the `fim_database_memory` property

        Args:
            value (bool): New value for the `fim_database_memory`.
        """
        self._fim_database_memory = value
