import engine_pb2 as _engine_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GraphGet_Request(_message.Message):
    __slots__ = ["policy", "type"]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    policy: str
    type: str
    def __init__(self, policy: _Optional[str] = ..., type: _Optional[str] = ...) -> None: ...

class GraphGet_Response(_message.Message):
    __slots__ = ["content", "error", "status"]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    content: str
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., content: _Optional[str] = ...) -> None: ...
