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
    __slots__ = ["entries", "error", "status"]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[MetricEntry]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[MetricEntry, _Mapping]]] = ...) -> None: ...

class Enable_Request(_message.Message):
    __slots__ = ["instrumentName", "status"]
    INSTRUMENTNAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    instrumentName: str
    status: bool
    def __init__(self, instrumentName: _Optional[str] = ..., status: bool = ...) -> None: ...

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
    __slots__ = ["instrumentName"]
    INSTRUMENTNAME_FIELD_NUMBER: _ClassVar[int]
    instrumentName: str
    def __init__(self, instrumentName: _Optional[str] = ...) -> None: ...

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
    type: int
    value: float
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., name: _Optional[str] = ..., type: _Optional[int] = ..., enabled: bool = ..., value: _Optional[float] = ...) -> None: ...

class List_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

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
    type: int
    value: float
    def __init__(self, name: _Optional[str] = ..., type: _Optional[int] = ..., enabled: bool = ..., value: _Optional[float] = ...) -> None: ...
