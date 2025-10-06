# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from dataclasses import dataclass, asdict, is_dataclass

from enum import Enum
from typing import List, Dict, Any

class ResourceType(str, Enum):
    """Enumeration for resource types in the catalog."""
    RULE = 'rule'
    DECODER = 'decoder'
    KVDB = 'kvdb'
    INTEGRATION = 'integration'

    def dirname(self) -> str:
        """Return the directory name corresponding to the resource type."""
        mapping = {
            self.RULE: 'rules',
            self.DECODER: 'decoders',
            self.KVDB: 'kvdbs',
            self.INTEGRATION: 'integrations'
        }
        return mapping.get(self)


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
    author: Author
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

    @classmethod
    def from_dict(cls, data: Dict) -> "Resource":
        """Create a Resource (or subclass) instance from a dictionary.
        
        Raises
        ------
        ResourceError
            If any required field is missing or invalid.
        """
        try:
            type_ = ResourceType(data["type"])
        except KeyError:
            raise ResourceError("Missing required field 'type' in resource data")
        except ValueError:
            raise ResourceError(f"Invalid resource type: {data.get('type')}")

        if type_ == ResourceType.DECODER:
            try:
                author_data = data["document"]["metadata"]["author"]
                metadata = Metadata(
                    author=Author(**author_data),
                    compatibility=data["document"]["metadata"]["compatibility"],
                    description=data["document"]["metadata"]["description"],
                    module=data["document"]["metadata"]["module"],
                    references=data["document"]["metadata"]["references"],
                    title=data["document"]["metadata"]["title"],
                    versions=data["document"]["metadata"]["versions"],
                )
                document = Document(metadata=metadata)
                status = Status(data["status"])
                return DecoderResource(
                    type=type_,
                    id=data["id"],
                    name=data["name"],
                    integration_id=data["integration_id"],
                    status=status,
                    document=document,
                )
            except KeyError as e:
                raise ResourceError(f"Missing required field: {e}") from e
            except ValueError as e:
                raise ResourceError(f"Invalid value for enum field: {e}") from e

        elif type_ == ResourceType.KVDB:
            try:
                return KVDBResource(
                    type=type_,
                    id=data["id"],
                    name=data["name"],
                    integration_id=data["integration_id"],
                    content=data["content"],
                )
            except KeyError as e:
                raise ResourceError(f"Missing required field: {e}") from e

        else:
            raise ResourceError(f"Unsupported resource type: {type_}")
        
    def to_dict(self) -> Dict:
        """Convert Resource (including nested dataclasses and enums) to a dictionary."""

        def serialize(obj):
            if isinstance(obj, Enum):
                return obj.value
            elif is_dataclass(obj):
                return {k: serialize(v) for k, v in asdict(obj).items()}
            elif isinstance(obj, list):
                return [serialize(v) for v in obj]
            elif isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            else:
                return obj

        return serialize(self)

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

class ResourceError(Exception):
    """Custom exception for resource creation errors."""

