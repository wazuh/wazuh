# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body


class UpdateConfigModel(Body):
    """UpdateConfig model."""
    def __init__(self, name: str = None, content: str = None):
        self.swagger_types = {
            'name': str,
            'content': str
        }

        self.attribute_map = {
            'name': 'name',
            'content': 'content'
        }

        self._name = name
        self._content = content

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, content):
        self._content = content