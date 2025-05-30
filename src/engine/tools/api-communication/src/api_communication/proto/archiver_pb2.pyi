import engine_pb2 as _engine_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ArchiverActivate_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ArchiverDeactivate_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ArchiverStatus_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ArchiverStatus_Response(_message.Message):
    __slots__ = ["active", "error", "status"]
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    active: bool
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., active: bool = ...) -> None: ...
