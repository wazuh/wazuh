import engine_pb2 as _engine_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Request(_message.Message):
    __slots__ = ["anyJSON", "defaultBool", "defaultInt", "defaultStr", "valueString"]
    ANYJSON_FIELD_NUMBER: _ClassVar[int]
    DEFAULTBOOL_FIELD_NUMBER: _ClassVar[int]
    DEFAULTINT_FIELD_NUMBER: _ClassVar[int]
    DEFAULTSTR_FIELD_NUMBER: _ClassVar[int]
    VALUESTRING_FIELD_NUMBER: _ClassVar[int]
    anyJSON: _struct_pb2.Value
    defaultBool: bool
    defaultInt: int
    defaultStr: str
    valueString: str
    def __init__(self, defaultStr: _Optional[str] = ..., defaultInt: _Optional[int] = ..., defaultBool: bool = ..., valueString: _Optional[str] = ..., anyJSON: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ...) -> None: ...

class Response(_message.Message):
    __slots__ = ["error", "status", "valueObj", "valueString"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUEOBJ_FIELD_NUMBER: _ClassVar[int]
    VALUESTRING_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    valueObj: _struct_pb2.Value
    valueString: str
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., valueObj: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ..., valueString: _Optional[str] = ...) -> None: ...
