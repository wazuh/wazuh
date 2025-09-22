# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from dataclasses import dataclass
from enum import Enum
from typing import List

class ResourceType(str, Enum):
    """Enumeration for resource types in the catalog.
    Values
    ------
    RULE : str
        Rule resource type.
    DECODER : str
        Decoder resource type.
    KVDB : str
        KVDB resource type.
    INTEGRATION : str
        Integration resource type.
    """
    RULE = 'rule'
    DECODER = 'decoder'
    KVDB = 'kvdb'
    INTEGRATION = 'integration'

class ResourceFormat(str, Enum):
    """Enumeration for resource formats in the catalog.
    Values
    ------
    JSON : str
        JSON format.
    YAML : str
        YAML format.
    YML : str
        YML format.
    XML : str
        XML format.
    """
    JSON = 'json'
    YAML = 'yaml'
    YML = 'yml'
    XML = 'xml'

class Status(str, Enum):
    """Enumeration for resource status values."""
    ENABLED = 'enabled'
    DISABLED = 'disabled'

@dataclass
class Author:
    """Class representing the author of a resource."""
    date: str
    name: str

@dataclass
class Metadata:
    """Class representing metadata for a resource."""
    author: dict
    compatibility: str
    description: str
    module: str
    references: List[str]
    title: str
    versions: List[str]

@dataclass
class Document:
    """Class representing the document structure of a resource."""
    metadata: Metadata

@dataclass
class Resource:
    """Class representing a resource in the catalog."""
    type: ResourceType
    integration_id: str
    id: str
    name: str
    status: Status
    document: Document
