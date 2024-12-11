import engine_pb2 as _engine_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Entry(_message.Message):
    __slots__ = ["key", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: _struct_pb2.Value
    def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ...) -> None: ...

class dbDelete_Request(_message.Message):
    __slots__ = ["key", "name"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    key: str
    name: str
    def __init__(self, name: _Optional[str] = ..., key: _Optional[str] = ...) -> None: ...

class dbGet_Request(_message.Message):
    __slots__ = ["key", "name"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    key: str
    name: str
    def __init__(self, name: _Optional[str] = ..., key: _Optional[str] = ...) -> None: ...

class dbGet_Response(_message.Message):
    __slots__ = ["error", "status", "value"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    value: _struct_pb2.Value
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., value: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ...) -> None: ...

class dbPut_Request(_message.Message):
    __slots__ = ["entry", "name"]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    entry: Entry
    name: str
    def __init__(self, name: _Optional[str] = ..., entry: _Optional[_Union[Entry, _Mapping]] = ...) -> None: ...

class dbSearch_Request(_message.Message):
    __slots__ = ["name", "page", "prefix", "records"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    name: str
    page: int
    prefix: str
    records: int
    def __init__(self, name: _Optional[str] = ..., prefix: _Optional[str] = ..., page: _Optional[int] = ..., records: _Optional[int] = ...) -> None: ...

class dbSearch_Response(_message.Message):
    __slots__ = ["entries", "error", "status"]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[Entry]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[Entry, _Mapping]]] = ...) -> None: ...

class managerDelete_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class managerDump_Request(_message.Message):
    __slots__ = ["name", "page", "records"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    name: str
    page: int
    records: int
    def __init__(self, name: _Optional[str] = ..., page: _Optional[int] = ..., records: _Optional[int] = ...) -> None: ...

class managerDump_Response(_message.Message):
    __slots__ = ["entries", "error", "status"]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[Entry]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[Entry, _Mapping]]] = ...) -> None: ...

class managerGet_Request(_message.Message):
    __slots__ = ["filter_by_name", "must_be_loaded"]
    FILTER_BY_NAME_FIELD_NUMBER: _ClassVar[int]
    MUST_BE_LOADED_FIELD_NUMBER: _ClassVar[int]
    filter_by_name: str
    must_be_loaded: bool
    def __init__(self, must_be_loaded: bool = ..., filter_by_name: _Optional[str] = ...) -> None: ...

class managerGet_Response(_message.Message):
    __slots__ = ["dbs", "error", "status"]
    DBS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    dbs: _containers.RepeatedScalarFieldContainer[str]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., dbs: _Optional[_Iterable[str]] = ...) -> None: ...

class managerPost_Request(_message.Message):
    __slots__ = ["name", "path"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...
