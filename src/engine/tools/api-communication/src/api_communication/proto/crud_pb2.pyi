import engine_pb2 as _engine_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ResourceSummary(_message.Message):
    __slots__ = ["name", "uuid"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    name: str
    uuid: str
    def __init__(self, uuid: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class namespaceDelete_Request(_message.Message):
    __slots__ = ["space"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    space: str
    def __init__(self, space: _Optional[str] = ...) -> None: ...

class namespaceGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class namespaceGet_Response(_message.Message):
    __slots__ = ["error", "spaces", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SPACES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    spaces: _containers.RepeatedScalarFieldContainer[str]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., spaces: _Optional[_Iterable[str]] = ...) -> None: ...

class namespaceImport_Request(_message.Message):
    __slots__ = ["force", "jsonContent", "space"]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    JSONCONTENT_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    force: bool
    jsonContent: str
    space: str
    def __init__(self, space: _Optional[str] = ..., jsonContent: _Optional[str] = ..., force: bool = ...) -> None: ...

class namespacePost_Request(_message.Message):
    __slots__ = ["space"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    space: str
    def __init__(self, space: _Optional[str] = ...) -> None: ...

class policyDelete_Request(_message.Message):
    __slots__ = ["space"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    space: str
    def __init__(self, space: _Optional[str] = ...) -> None: ...

class policyPost_Request(_message.Message):
    __slots__ = ["space", "ymlContent"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    YMLCONTENT_FIELD_NUMBER: _ClassVar[int]
    space: str
    ymlContent: str
    def __init__(self, space: _Optional[str] = ..., ymlContent: _Optional[str] = ...) -> None: ...

class policyValidate_Request(_message.Message):
    __slots__ = ["full_policy", "load_in_tester"]
    FULL_POLICY_FIELD_NUMBER: _ClassVar[int]
    LOAD_IN_TESTER_FIELD_NUMBER: _ClassVar[int]
    full_policy: _struct_pb2.Struct
    load_in_tester: bool
    def __init__(self, load_in_tester: bool = ..., full_policy: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class resourceDelete_Request(_message.Message):
    __slots__ = ["space", "uuid"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    space: str
    uuid: str
    def __init__(self, space: _Optional[str] = ..., uuid: _Optional[str] = ...) -> None: ...

class resourceGet_Request(_message.Message):
    __slots__ = ["asJson", "space", "uuid"]
    ASJSON_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    asJson: bool
    space: str
    uuid: str
    def __init__(self, space: _Optional[str] = ..., uuid: _Optional[str] = ..., asJson: bool = ...) -> None: ...

class resourceGet_Response(_message.Message):
    __slots__ = ["content", "error", "status"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    content: str
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., content: _Optional[str] = ...) -> None: ...

class resourceList_Request(_message.Message):
    __slots__ = ["space", "type"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    space: str
    type: str
    def __init__(self, space: _Optional[str] = ..., type: _Optional[str] = ...) -> None: ...

class resourceList_Response(_message.Message):
    __slots__ = ["error", "resources", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    resources: _containers.RepeatedCompositeFieldContainer[ResourceSummary]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., resources: _Optional[_Iterable[_Union[ResourceSummary, _Mapping]]] = ...) -> None: ...

class resourcePost_Request(_message.Message):
    __slots__ = ["space", "type", "ymlContent"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    YMLCONTENT_FIELD_NUMBER: _ClassVar[int]
    space: str
    type: str
    ymlContent: str
    def __init__(self, space: _Optional[str] = ..., type: _Optional[str] = ..., ymlContent: _Optional[str] = ...) -> None: ...

class resourceValidate_Request(_message.Message):
    __slots__ = ["resource", "type"]
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    resource: _struct_pb2.Struct
    type: str
    def __init__(self, type: _Optional[str] = ..., resource: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...
