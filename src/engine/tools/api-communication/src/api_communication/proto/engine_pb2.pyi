from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
ERROR: ReturnStatus
OK: ReturnStatus
UNKNOWN: ReturnStatus

class GenericStatus_Response(_message.Message):
    __slots__ = ["error", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: ReturnStatus
    def __init__(self, status: _Optional[_Union[ReturnStatus, str]] = ..., error: _Optional[str] = ...) -> None: ...

class ReturnStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
