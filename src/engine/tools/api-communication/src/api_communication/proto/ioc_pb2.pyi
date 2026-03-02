import engine_pb2 as _engine_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetIocState_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class GetIocState_Response(_message.Message):
    __slots__ = ["hash", "lastError", "status", "updating"]
    HASH_FIELD_NUMBER: _ClassVar[int]
    LASTERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    UPDATING_FIELD_NUMBER: _ClassVar[int]
    hash: str
    lastError: str
    status: _engine_pb2.ReturnStatus
    updating: bool
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., hash: _Optional[str] = ..., updating: bool = ..., lastError: _Optional[str] = ...) -> None: ...

class UpdateIoc_Request(_message.Message):
    __slots__ = ["hash", "path"]
    HASH_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    hash: str
    path: str
    def __init__(self, path: _Optional[str] = ..., hash: _Optional[str] = ...) -> None: ...
