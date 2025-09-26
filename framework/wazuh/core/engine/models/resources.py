# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any

class ResourceType(str, Enum):
    """Enumeration for resource types in the catalog."""
    RULE = 'rule'
    DECODER = 'decoder'
    KVDB = 'kvdb'
    INTEGRATION = 'integration'

class ResourceFormat(str, Enum):
    """Enumeration for resource formats in the catalog."""
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
    """Base resource model."""
    type: ResourceType
    id: str
    name: str

@dataclass
class WithIntegrationId:
    """Adds integration_id to resources."""
    integration_id: str

@dataclass
class KVDBResource(Resource, WithIntegrationId):
    """KVDB resource."""
    content: Dict[str, Any]

@dataclass
class DecoderResource(Resource, WithIntegrationId):
    """Decoder resource."""
    status: Status
    document: Document
