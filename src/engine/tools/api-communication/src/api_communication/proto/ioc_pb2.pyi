import engine_pb2 as _engine_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class UpdateIoc_Request(_message.Message):
    __slots__ = ["hash", "path"]
    HASH_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    hash: str
    path: str
    def __init__(self, path: _Optional[str] = ..., hash: _Optional[str] = ...) -> None: ...
