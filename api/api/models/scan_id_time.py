# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from api.models.base_model_ import Model
from api import util


class ScanIdTime(Model):

    def __init__(self, id: int = None, time: str = None):
        """ScanIdTime - a model defined in Swagger

        :param id: Scan ID.
        :param time: Date when the scan was performed
        """
        self.swagger_types = {
            'id': int,
            'time': str
        }

        self.attribute_map = {
            'id': 'id',
            'time': 'time'
        }

        self._id = id
        self._time = time

    @classmethod
    def from_dict(cls, dikt) -> 'ScanIdTime':
        """Returns the dict as a model

        :param dikt: A dict.
        :return: The ScanIdTime of this ScanIdTime
        """
        return util.deserialize_model(dikt, cls)

    @property
    def id(self) -> int:
        """Gets the id of this ScanIdTime

        :return: The id of this ScanIdTime
        """
        return self._id

    @id.setter
    def id(self, id: int):
        """Sets the id of this ScanIdTime

        :param id: The id of this ScanIdTime
        """
        self._id = id

    @property
    def time(self) -> str:
        """Gets the time of this ScanIdTime

        :return: The time of this ScanIdTime
        """
        return self._time

    @time.setter
    def time(self, time: str):
        """Sets the time of this ScanIdTime

        :param time: The time of this ScanIdTime
        """
        self._time = time
