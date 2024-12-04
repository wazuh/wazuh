import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

ALL: TraceLevel
ASSET_ONLY: TraceLevel
DESCRIPTOR: _descriptor.FileDescriptor
DISABLED: State
ENABLED: State
ERROR: Sync
NONE: TraceLevel
OUTDATED: Sync
STATE_UNKNOWN: State
SYNC_UNKNOWN: Sync
UPDATED: Sync

class Result(_message.Message):
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
    asset_traces: _containers.RepeatedCompositeFieldContainer[Result.AssetTrace]
    output: str
    def __init__(self, output: _Optional[str] = ..., asset_traces: _Optional[_Iterable[_Union[Result.AssetTrace, _Mapping]]] = ...) -> None: ...

class RunPost_Request(_message.Message):
    __slots__ = ["asset_trace", "name", "namespaces", "ndjson_event", "trace_level"]
    ASSET_TRACE_FIELD_NUMBER: _ClassVar[int]
    NAMESPACES_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NDJSON_EVENT_FIELD_NUMBER: _ClassVar[int]
    TRACE_LEVEL_FIELD_NUMBER: _ClassVar[int]
    asset_trace: _containers.RepeatedScalarFieldContainer[str]
    name: str
    namespaces: _containers.RepeatedScalarFieldContainer[str]
    ndjson_event: str
    trace_level: TraceLevel
    def __init__(self, name: _Optional[str] = ..., ndjson_event: _Optional[str] = ..., trace_level: _Optional[_Union[TraceLevel, str]] = ..., asset_trace: _Optional[_Iterable[str]] = ..., namespaces: _Optional[_Iterable[str]] = ...) -> None: ...

class RunPost_Response(_message.Message):
    __slots__ = ["error", "result", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    result: Result
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., result: _Optional[_Union[Result, _Mapping]] = ...) -> None: ...

class Session(_message.Message):
    __slots__ = ["description", "entry_status", "last_use", "lifetime", "name", "policy", "policy_sync"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ENTRY_STATUS_FIELD_NUMBER: _ClassVar[int]
    LAST_USE_FIELD_NUMBER: _ClassVar[int]
    LIFETIME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    POLICY_SYNC_FIELD_NUMBER: _ClassVar[int]
    description: str
    entry_status: State
    last_use: int
    lifetime: int
    name: str
    policy: str
    policy_sync: Sync
    def __init__(self, name: _Optional[str] = ..., policy: _Optional[str] = ..., lifetime: _Optional[int] = ..., description: _Optional[str] = ..., policy_sync: _Optional[_Union[Sync, str]] = ..., entry_status: _Optional[_Union[State, str]] = ..., last_use: _Optional[int] = ...) -> None: ...

class SessionDelete_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

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

class SessionPost(_message.Message):
    __slots__ = ["description", "lifetime", "name", "policy"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LIFETIME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    description: str
    lifetime: int
    name: str
    policy: str
    def __init__(self, name: _Optional[str] = ..., policy: _Optional[str] = ..., lifetime: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class SessionPost_Request(_message.Message):
    __slots__ = ["session"]
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: SessionPost
    def __init__(self, session: _Optional[_Union[SessionPost, _Mapping]] = ...) -> None: ...

class SessionReload_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class TableGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class TableGet_Response(_message.Message):
    __slots__ = ["error", "sessions", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    sessions: _containers.RepeatedCompositeFieldContainer[Session]
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., sessions: _Optional[_Iterable[_Union[Session, _Mapping]]] = ...) -> None: ...

class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Sync(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class TraceLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
