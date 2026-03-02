import engine_pb2 as _engine_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class GetIocState_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class GetIocState_Response(_message.Message):
    __slots__ = ["error", "hash", "updating"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    UPDATING_FIELD_NUMBER: _ClassVar[int]
    error: str
    hash: str
    updating: bool
    def __init__(self, hash: _Optional[str] = ..., updating: bool = ..., error: _Optional[str] = ...) -> None: ...

class UpdateIoc_Request(_message.Message):
    __slots__ = ["hash", "path"]
    HASH_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    hash: str
    path: str
    def __init__(self, path: _Optional[str] = ..., hash: _Optional[str] = ...) -> None: ...
