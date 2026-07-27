import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ResourceState(_message.Message):
    __slots__ = ["available", "hash", "last_successful_update", "status"]
    AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    LAST_SUCCESSFUL_UPDATE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    available: bool
    hash: str
    last_successful_update: int
    status: str
    def __init__(self, available: bool = ..., status: _Optional[str] = ..., hash: _Optional[str] = ..., last_successful_update: _Optional[int] = ...) -> None: ...

class SpaceState(_message.Message):
    __slots__ = ["available", "enabled", "hash", "last_successful_update", "status"]
    AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    LAST_SUCCESSFUL_UPDATE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    available: bool
    enabled: bool
    hash: str
    last_successful_update: int
    status: str
    def __init__(self, available: bool = ..., enabled: bool = ..., status: _Optional[str] = ..., hash: _Optional[str] = ..., last_successful_update: _Optional[int] = ...) -> None: ...

class StatusGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class StatusGet_Response(_message.Message):
    __slots__ = ["error", "geo", "ioc", "ready", "spaces", "status"]
    class GeoEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ResourceState
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ResourceState, _Mapping]] = ...) -> None: ...
    class IocEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ResourceState
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ResourceState, _Mapping]] = ...) -> None: ...
    class SpacesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: SpaceState
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[SpaceState, _Mapping]] = ...) -> None: ...
    ERROR_FIELD_NUMBER: _ClassVar[int]
    GEO_FIELD_NUMBER: _ClassVar[int]
    IOC_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    SPACES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    geo: _containers.MessageMap[str, ResourceState]
    ioc: _containers.MessageMap[str, ResourceState]
    ready: bool
    spaces: _containers.MessageMap[str, SpaceState]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., ready: bool = ..., spaces: _Optional[_Mapping[str, SpaceState]] = ..., ioc: _Optional[_Mapping[str, ResourceState]] = ..., geo: _Optional[_Mapping[str, ResourceState]] = ...) -> None: ...
