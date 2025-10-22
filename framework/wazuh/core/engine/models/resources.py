# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from dataclasses import dataclass, asdict, is_dataclass

from enum import Enum
from typing import List, Dict, Any

from wazuh.core.exception import WazuhError


class ResourceType(str, Enum):
    """Enumeration for resource types in the catalog."""

    DECODER = "decoder"
    KVDB = "kvdb"
    INTEGRATION = "integration"
    INTEGRATIONS_ORDER = "integrations_order"

    def dirname(self) -> str:
        """Return the directory name corresponding to the resource type."""
        mapping = {self.DECODER: "decoders", self.INTEGRATION: "integrations", self.INTEGRATIONS_ORDER: "integrations"}
        return mapping.get(self)


class ResourceFormat(str, Enum):
    """Enumeration for resource formats in the catalog."""

    JSON = "json"
    YAML = "yaml"
    YML = "yml"
    XML = "xml"


class Status(str, Enum):
    """Enumeration for resource status values."""

    ENABLED = "enabled"
    DISABLED = "disabled"


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
        WazuhError
            If any required field is missing or invalid.
        """
        try:
            type_ = ResourceType(data["type"])
            match type_:
                case ResourceType.DECODER:
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
                case ResourceType.KVDB:
                    return KVDBResource(
                        type=type_,
                        id=data["id"],
                        name=data["name"],
                        integration_id=data["integration_id"],
                        content=data["content"],
                    )
                case ResourceType.INTEGRATION:
                    return IntegrationResource(
                        type=type_,
                        id=data["id"],
                        name=data["name"],
                        description=data["description"],
                        documentation=data["documentation"],
                        status=data["status"],
                        kvdbs=data["kvdbs"],
                        decoders=data["decoders"],
                    )
        except KeyError as e:
            raise WazuhError(9001, extra_message={"resource_type": type_, "cause": str(e)}) from e
        except ValueError as e:
            raise WazuhError(9001, extra_message={"resource_type": type_, "cause": str(e)}) from e

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


@dataclass
class IntegrationResource(Resource):
    description: str
    documentation: str
    status: Status
    kvdbs: List
    decoders: List
