import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DbDelete_Request(_message.Message):
    __slots__ = ["path"]
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class DbEntry(_message.Message):
    __slots__ = ["name", "path", "type"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    type: str
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., type: _Optional[str] = ...) -> None: ...

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

class DbPost_Request(_message.Message):
    __slots__ = ["path", "type"]
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    path: str
    type: str
    def __init__(self, path: _Optional[str] = ..., type: _Optional[str] = ...) -> None: ...

class DbRemoteUpsert_Request(_message.Message):
    __slots__ = ["dbUrl", "hashUrl", "path", "type"]
    DBURL_FIELD_NUMBER: _ClassVar[int]
    HASHURL_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    dbUrl: str
    hashUrl: str
    path: str
    type: str
    def __init__(self, path: _Optional[str] = ..., type: _Optional[str] = ..., dbUrl: _Optional[str] = ..., hashUrl: _Optional[str] = ...) -> None: ...
