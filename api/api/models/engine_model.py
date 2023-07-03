# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body

class AddCatalogResourceModel(Body):
    """AddCatalogResource model."""
    def __init__(self, resource_type: str = None, resource_format: str = None, content: str = None):
        self.swagger_types = {
            'resource_type': str,
            'resource_format': str,
            'content': str
        }

        self.attribute_map = {
            'resource_type': 'resource_type',
            'resource_format': 'resource_format',
            'content': 'content'
        }

        self._resource_type = resource_type
        self._resource_format = resource_format
        self._content = content

    @property
    def resource_type(self):
        return self._resource_type

    @resource_type.setter
    def resource_type(self, resource_type):
        self._resource_type = resource_type

    @property
    def resource_format(self):
        return self._resource_format

    @resource_format.setter
    def resource_format(self, resource_format):
        self._resource_format = resource_format
    
    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, content):
        self._content = content

class UpdateCatalogResourceModel(Body):
    """UpdateCatalogResource model."""
    def __init__(self, name: str = None, resource_format: str = None, content: str = None):
        self.swagger_types = {
            'name': str,
            'resource_format': str,
            'content': str
        }

        self.attribute_map = {
            'name': 'name',
            'resource_format': 'resource_format',
            'content': 'content'
        }

        self._name = name
        self._resource_format = resource_format
        self._content = content

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def resource_format(self):
        return self._resource_format

    @resource_format.setter
    def resource_format(self, resource_format):
        self._resource_format = resource_format
    
    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, content):
        self._content = content
