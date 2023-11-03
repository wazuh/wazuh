import engine_pb2 as _engine_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
OUTPUT_AND_TRACES: DebugMode
OUTPUT_AND_TRACES_WITH_DETAILS: DebugMode
OUTPUT_ONLY: DebugMode

class Run(_message.Message):
    __slots__ = ["asset_traces", "output"]
    class AssetTrace(_message.Message):
        __slots__ = ["asset", "success", "traces"]
        ASSET_FIELD_NUMBER: _ClassVar[int]
        SUCCESS_FIELD_NUMBER: _ClassVar[int]
        TRACES_FIELD_NUMBER: _ClassVar[int]
        asset: str
        success: bool
        traces: _containers.RepeatedScalarFieldContainer[str]
        def __init__(self, asset: _Optional[str] = ..., success: bool = ..., traces: _Optional[_Iterable[str]] = ...) -> None: ...
    ASSET_TRACES_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    asset_traces: _containers.RepeatedCompositeFieldContainer[Run.AssetTrace]
    output: _struct_pb2.Value
    def __init__(self, output: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ..., asset_traces: _Optional[_Iterable[_Union[Run.AssetTrace, _Mapping]]] = ...) -> None: ...

class RunPost_Request(_message.Message):
    __slots__ = ["asset_trace", "debug_mode", "event", "name", "namespaces", "protocol_location", "protocol_queue"]
    ASSET_TRACE_FIELD_NUMBER: _ClassVar[int]
    DEBUG_MODE_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    NAMESPACES_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_LOCATION_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_QUEUE_FIELD_NUMBER: _ClassVar[int]
    asset_trace: _containers.RepeatedScalarFieldContainer[str]
    debug_mode: DebugMode
    event: _struct_pb2.Value
    name: str
    namespaces: _containers.RepeatedScalarFieldContainer[str]
    protocol_location: str
    protocol_queue: str
    def __init__(self, name: _Optional[str] = ..., event: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ..., protocol_queue: _Optional[str] = ..., debug_mode: _Optional[_Union[DebugMode, str]] = ..., asset_trace: _Optional[_Iterable[str]] = ..., protocol_location: _Optional[str] = ..., namespaces: _Optional[_Iterable[str]] = ...) -> None: ...

class RunPost_Response(_message.Message):
    __slots__ = ["error", "run", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    RUN_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    run: Run
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., run: _Optional[_Union[Run, _Mapping]] = ...) -> None: ...

class Session(_message.Message):
    __slots__ = ["creation_date", "description", "filter", "id", "lifespan", "name", "policy", "route"]
    CREATION_DATE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    LIFESPAN_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    creation_date: int
    description: str
    filter: str
    id: int
    lifespan: int
    name: str
    policy: str
    route: str
    def __init__(self, name: _Optional[str] = ..., id: _Optional[int] = ..., creation_date: _Optional[int] = ..., policy: _Optional[str] = ..., filter: _Optional[str] = ..., route: _Optional[str] = ..., lifespan: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class SessionGet_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class SessionGet_Response(_message.Message):
    __slots__ = ["error", "session", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SESSION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    session: Session
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., session: _Optional[_Union[Session, _Mapping]] = ...) -> None: ...

class SessionPost_Request(_message.Message):
    __slots__ = ["description", "lifespan", "name", "policy"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LIFESPAN_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    description: str
    lifespan: int
    name: str
    policy: str
    def __init__(self, name: _Optional[str] = ..., policy: _Optional[str] = ..., lifespan: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class SessionPost_Response(_message.Message):
    __slots__ = ["error"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    error: str
    def __init__(self, error: _Optional[str] = ...) -> None: ...

class SessionsDelete_Request(_message.Message):
    __slots__ = ["delete_all", "name"]
    DELETE_ALL_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    delete_all: bool
    name: str
    def __init__(self, name: _Optional[str] = ..., delete_all: bool = ...) -> None: ...

class SessionsDelete_Response(_message.Message):
    __slots__ = ["error"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    error: str
    def __init__(self, error: _Optional[str] = ...) -> None: ...

class SessionsGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class SessionsGet_Response(_message.Message):
    __slots__ = ["error", "list", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    LIST_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    list: _containers.RepeatedScalarFieldContainer[str]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., list: _Optional[_Iterable[str]] = ...) -> None: ...

class DebugMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
