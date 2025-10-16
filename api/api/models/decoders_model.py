# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body, Model


class Author(Model):
    def __init__(self, date: str = None, name: str = None):
        self.swagger_types = {
            'date': str,
            'name': str
        }

        self.attribute_map = {
            'date': 'date',
            'name': 'name'
        }

        self._date = date
        self._name = name

    @property
    def date(self):
        return self._date

    @date.setter
    def date(self, date):
        self._date = date

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name


class Metadata(Model):
    def __init__(
        self,
        author: Dict = None,
        compatibility: str = None,
        description: str = None,
        module: str = None,
        references: List[str] = None,
        title: str = None,
        versions: List[str] = None
    ):
        self.swagger_types = {
            'author': Author,
            'compatibility': str,
            'description': str,
            'module': str,
            'references': List[str],
            'title': str,
            'versions': List[str]
        }

        self.attribute_map = {
            'author': 'author',
            'compatibility': 'compatibility',
            'description': 'description',
            'module': 'module',
            'references': 'references',
            'title': 'title',
            'versions': 'versions'
        }

        self._author = Author(**author or {}).to_dict()
        self._compatibility = compatibility
        self._description = description
        self._module = module
        self._references = references or []
        self._title = title
        self._versions = versions or []

    @property
    def author(self):
        return self._author

    @author.setter
    def author(self, author):
        self._author = author

    @property
    def compatibility(self):
        return self._compatibility

    @compatibility.setter
    def compatibility(self, compatibility):
        self._compatibility = compatibility

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def module(self):
        return self._module

    @module.setter
    def module(self, module):
        self._module = module

    @property
    def references(self):
        return self._references

    @references.setter
    def references(self, references):
        self._references = references

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, title):
        self._title = title

    @property
    def versions(self):
        return self._versions

    @versions.setter
    def versions(self, versions):
        self._versions = versions


class Document(Model):
    def __init__(self, metadata: Dict = None):
        self.swagger_types = {
            'metadata': Metadata
        }

        self.attribute_map = {
            'metadata': 'metadata'
        }

        self._metadata = Metadata(**metadata or {}).to_dict()

    @property
    def metadata(self):
        return self._metadata

    @metadata.setter
    def metadata(self, metadata):
        self._metadata = metadata


class DecodersModel(Body):
    def __init__(
        self,
        type: str = None,
        integration_id: str = None,
        id: str = None,
        name: str = None,
        status: str = None,
        document: Dict = None
    ):
        self.swagger_types = {
            'type': str,
            'integration_id': str,
            'id': str,
            'name': str,
            'status': str,
            'document': Document
        }

        self.attribute_map = {
            'type': 'type',
            'integration_id': 'integration_id',
            'id': 'id',
            'name': 'name',
            'status': 'status',
            'document': 'document'
        }

        self._type = type
        self._integration_id = integration_id
        self._id = id
        self._name = name
        self._status = status
        self._document = Document(**document or {}).to_dict()

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, type):
        self._type = type

    @property
    def integration_id(self):
        return self._integration_id

    @integration_id.setter
    def integration_id(self, integration_id):
        self._integration_id = integration_id

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def document(self):
        return self._document

    @document.setter
    def document(self, document):
        self._document = document
