import engine_pb2 as _engine_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Dump_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class Dump_Response(_message.Message):
    __slots__ = ["error", "status", "value"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    value: _struct_pb2.Value
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., value: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ...) -> None: ...

class Enable_Request(_message.Message):
    __slots__ = ["instrumentName", "scopeName", "status"]
    INSTRUMENTNAME_FIELD_NUMBER: _ClassVar[int]
    SCOPENAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    instrumentName: str
    scopeName: str
    status: bool
    def __init__(self, scopeName: _Optional[str] = ..., instrumentName: _Optional[str] = ..., status: bool = ...) -> None: ...

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
    __slots__ = ["instrumentName", "scopeName"]
    INSTRUMENTNAME_FIELD_NUMBER: _ClassVar[int]
    SCOPENAME_FIELD_NUMBER: _ClassVar[int]
    instrumentName: str
    scopeName: str
    def __init__(self, scopeName: _Optional[str] = ..., instrumentName: _Optional[str] = ...) -> None: ...

class Get_Response(_message.Message):
    __slots__ = ["error", "status", "value"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    value: _struct_pb2.Value
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., value: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ...) -> None: ...

class List_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class List_Response(_message.Message):
    __slots__ = ["error", "status", "value"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    value: _struct_pb2.Value
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., value: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ...) -> None: ...

class Test_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class Test_Response(_message.Message):
    __slots__ = ["content", "error", "status"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    content: _containers.RepeatedScalarFieldContainer[str]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., content: _Optional[_Iterable[str]] = ...) -> None: ...
