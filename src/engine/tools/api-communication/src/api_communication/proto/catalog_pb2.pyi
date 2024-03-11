import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
UNKNOWN: ResourceType
collection: ResourceType
decoder: ResourceType
filter: ResourceType
integration: ResourceType
json: ResourceFormat
output: ResourceType
rule: ResourceType
schema: ResourceType
yaml: ResourceFormat
yml: ResourceFormat

class NamespacesGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class NamespacesGet_Response(_message.Message):
    __slots__ = ["error", "namespaces", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NAMESPACES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    namespaces: _containers.RepeatedScalarFieldContainer[str]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., namespaces: _Optional[_Iterable[str]] = ...) -> None: ...

class ResourceDelete_Request(_message.Message):
    __slots__ = ["name", "namespaceid"]
    NAMESPACEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    namespaceid: str
    def __init__(self, name: _Optional[str] = ..., namespaceid: _Optional[str] = ...) -> None: ...

class ResourceGet_Request(_message.Message):
    __slots__ = ["format", "name", "namespaceid"]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    NAMESPACEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    format: ResourceFormat
    name: str
    namespaceid: str
    def __init__(self, name: _Optional[str] = ..., format: _Optional[_Union[ResourceFormat, str]] = ..., namespaceid: _Optional[str] = ...) -> None: ...

class ResourceGet_Response(_message.Message):
    __slots__ = ["content", "error", "status"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    content: str
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., content: _Optional[str] = ...) -> None: ...

class ResourcePost_Request(_message.Message):
    __slots__ = ["content", "format", "namespaceid", "type"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    NAMESPACEID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    content: str
    format: ResourceFormat
    namespaceid: str
    type: ResourceType
    def __init__(self, type: _Optional[_Union[ResourceType, str]] = ..., format: _Optional[_Union[ResourceFormat, str]] = ..., content: _Optional[str] = ..., namespaceid: _Optional[str] = ...) -> None: ...

class ResourcePut_Request(_message.Message):
    __slots__ = ["content", "format", "name", "namespaceid"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    NAMESPACEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    content: str
    format: ResourceFormat
    name: str
    namespaceid: str
    def __init__(self, name: _Optional[str] = ..., format: _Optional[_Union[ResourceFormat, str]] = ..., content: _Optional[str] = ..., namespaceid: _Optional[str] = ...) -> None: ...

class ResourceValidate_Request(_message.Message):
    __slots__ = ["content", "format", "name", "namespaceid"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    NAMESPACEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    content: str
    format: ResourceFormat
    name: str
    namespaceid: str
    def __init__(self, name: _Optional[str] = ..., format: _Optional[_Union[ResourceFormat, str]] = ..., content: _Optional[str] = ..., namespaceid: _Optional[str] = ...) -> None: ...

class ResourceFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class ResourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
