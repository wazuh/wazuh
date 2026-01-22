import engine_pb2 as _engine_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DbEntry(_message.Message):
    __slots__ = ["createdAt", "hash", "name", "path", "type"]
    CREATEDAT_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    createdAt: str
    hash: str
    name: str
    path: str
    type: str
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., hash: _Optional[str] = ..., createdAt: _Optional[str] = ..., type: _Optional[str] = ...) -> None: ...

class DbGet_Request(_message.Message):
    __slots__ = ["ip"]
    IP_FIELD_NUMBER: _ClassVar[int]
    ip: str
    def __init__(self, ip: _Optional[str] = ...) -> None: ...

class DbGet_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: _struct_pb2.Struct
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class DbList_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class DbList_Response(_message.Message):
    __slots__ = ["entries", "error", "status"]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[DbEntry]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[DbEntry, _Mapping]]] = ...) -> None: ...
