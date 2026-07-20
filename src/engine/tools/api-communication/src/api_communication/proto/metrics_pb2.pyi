import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Dump_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class Dump_Response(_message.Message):
    __slots__ = ["error", "name", "spaces", "status", "timestamp", "uptime"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SPACES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    UPTIME_FIELD_NUMBER: _ClassVar[int]
    error: str
    name: str
    spaces: _containers.RepeatedCompositeFieldContainer[SpaceMetrics]
    status: _engine_pb2.ReturnStatus
    timestamp: str
    uptime: str
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., name: _Optional[str] = ..., uptime: _Optional[str] = ..., timestamp: _Optional[str] = ..., spaces: _Optional[_Iterable[_Union[SpaceMetrics, _Mapping]]] = ..., **kwargs) -> None: ...

class Enable_Request(_message.Message):
    __slots__ = ["instrumentName", "space", "status"]
    INSTRUMENTNAME_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    instrumentName: str
    space: str
    status: bool
    def __init__(self, instrumentName: _Optional[str] = ..., status: bool = ..., space: _Optional[str] = ...) -> None: ...

class Enable_Response(_message.Message):
    __slots__ = ["content", "error", "status"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    content: str
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., content: _Optional[str] = ...) -> None: ...

class Get_Request(_message.Message):
    __slots__ = ["instrumentName", "space"]
    INSTRUMENTNAME_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    instrumentName: str
    space: str
    def __init__(self, instrumentName: _Optional[str] = ..., space: _Optional[str] = ...) -> None: ...

class Get_Response(_message.Message):
    __slots__ = ["enabled", "error", "name", "status", "type", "value"]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    error: str
    name: str
    status: _engine_pb2.ReturnStatus
    type: str
    value: float
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., name: _Optional[str] = ..., type: _Optional[str] = ..., enabled: bool = ..., value: _Optional[float] = ...) -> None: ...

class List_Request(_message.Message):
    __slots__ = ["space"]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    space: str
    def __init__(self, space: _Optional[str] = ...) -> None: ...

class List_Response(_message.Message):
    __slots__ = ["error", "names", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    names: _containers.RepeatedScalarFieldContainer[str]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., names: _Optional[_Iterable[str]] = ...) -> None: ...

class MetricEntry(_message.Message):
    __slots__ = ["enabled", "name", "type", "value"]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    name: str
    type: str
    value: float
    def __init__(self, name: _Optional[str] = ..., type: _Optional[str] = ..., enabled: bool = ..., value: _Optional[float] = ...) -> None: ...

class SpaceMetrics(_message.Message):
    __slots__ = ["metrics", "name"]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    metrics: _containers.RepeatedCompositeFieldContainer[MetricEntry]
    name: str
    def __init__(self, name: _Optional[str] = ..., metrics: _Optional[_Iterable[_Union[MetricEntry, _Mapping]]] = ...) -> None: ...
