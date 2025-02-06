# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from __future__ import absolute_import

from server_management_api import util
from server_management_api.models.base_model_ import Model


class BasicInfo(Model):

    def __init__(self, title: str = None, api_version: str = None, revision: int = None, license_name: str = None,
                 license_url: str = None, hostname: str = None, timestamp:  str = None):
        """BasicInfo - a model defined in Swagger

        :param title: API title name.
        :type title: str

        :param api_version: API version installed in the node.
        :type api_version: str

        :param revision: Revision.
        :type revision: str

        :param license_name: API license name.
        :type license_name: str

        :param license_url: API license url.
        :type license_url: str

        :param hostname: Machine´s hostname.
        :type hostname: str

        :param timestamp: Timestamp.
        :type timestamp: str
        """
        self.swagger_types = {
            'title': str,
            'api_version': str,
            'revision': int,
            'license_name': str,
            'license_url': str,
            'hostname': str,
            'timestamp': str
        }

        self.attribute_map = {
            'title': 'title',
            'api_version': 'api_version',
            'revision': 'revision',
            'license_name': 'license_name',
            'license_url': 'license_url',
            'hostname': 'hostname',
            'timestamp': 'timestamp'
        }

        self._title = title
        self._api_version = api_version
        self._revision = revision
        self._license_name = license_name
        self._license_url = license_url
        self._hostname = hostname
        self._timestamp = timestamp

    @classmethod
    def from_dict(cls, dikt) -> 'BasicInfo':
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The BasicInfo of this BasicInfo.
        :rtype: BasicInfo
        """
        return util.deserialize_model(dikt, cls)

    @property
    def title(self) -> str:
        """Gets the title of this BasicInfo.

        :return: The title of this BasicInfo.
        :rtype: str
        """
        return self._title

    @title.setter
    def title(self, title: str):
        """Sets the title of this BasicInfo.

        :param title: The title of this BasicInfo.
        :type title: str
        """
        self._title = title

    @property
    def api_version(self) -> str:
        """Gets the api_version of this BasicInfo.

        :return: The api_version of this BasicInfo.
        :rtype: str
        """
        return self._api_version

    @api_version.setter
    def api_version(self, api_version: str):
        """Sets the api_version of this BasicInfo.

        :param api_version: The api_version of this BasicInfo.
        :type api_version: str
        """
        self._api_version = api_version

    @property
    def revision(self) -> int:
        """Gets the revision of this BasicInfo.

        :return: The revision of this BasicInfo.
        :rtype: int
        """
        return self._revision

    @revision.setter
    def revision(self, revision: int):
        """Sets the revision of this BasicInfo.

        :param revision: The revision of this BasicInfo.
        :type revision: int
        """
        self._revision = revision

    @property
    def license_name(self) -> str:
        """Gets the license_name of this BasicInfo.

        :return: The license_name of this BasicInfo.
        :rtype: str
        """
        return self._license_name

    @license_name.setter
    def license_name(self, license_name: str):
        """Sets the license_name of this BasicInfo.

        :param license_name: The license_name of this BasicInfo.
        :type license_name: str
        """
        self._license_name = license_name

    @property
    def license_url(self) -> str:
        """Gets the license_url of this BasicInfo.

        :return: The license_url of this BasicInfo.
        :rtype: str
        """
        return self._license_url

    @license_url.setter
    def license_url(self, license_url: str):
        """Sets the license_url of this BasicInfo.

        :param license_url: The license_url of this BasicInfo.
        :type license_url: str
        """
        self._license_url = license_url

    @property
    def hostname(self) -> str:
        """Gets the hostname of this BasicInfo.

        :return: The hostname of this BasicInfo.
        :rtype: str
        """
        return self._hostname

    @hostname.setter
    def hostname(self, hostname: str):
        """Sets the hostname of this BasicInfo.

        :param hostname: The hostname of this BasicInfo.
        :type hostname: str
        """
        self._hostname = hostname

    @property
    def timestamp(self) -> str:
        """Gets the timestamp of this BasicInfo.

        :return: The timestamp of this BasicInfo.
        :rtype: str
        """
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp: str):
        """Sets the timestamp of this BasicInfo.

        :param timestamp: The timestamp of this BasicInfo.
        :type timestamp: str
        """
        self._timestamp = timestamp
