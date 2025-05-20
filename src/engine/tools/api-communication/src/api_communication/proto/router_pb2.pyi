import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
DISABLED: State
ENABLED: State
ERROR: Sync
OUTDATED: Sync
STATE_UNKNOWN: State
SYNC_UNKNOWN: Sync
UPDATED: Sync

class Entry(_message.Message):
    __slots__ = ["description", "entry_status", "filter", "name", "policy", "policy_sync", "priority", "uptime"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ENTRY_STATUS_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    POLICY_SYNC_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    UPTIME_FIELD_NUMBER: _ClassVar[int]
    description: str
    entry_status: State
    filter: str
    name: str
    policy: str
    policy_sync: Sync
    priority: int
    uptime: int
    def __init__(self, name: _Optional[str] = ..., policy: _Optional[str] = ..., filter: _Optional[str] = ..., priority: _Optional[int] = ..., description: _Optional[str] = ..., policy_sync: _Optional[_Union[Sync, str]] = ..., entry_status: _Optional[_Union[State, str]] = ..., uptime: _Optional[int] = ...) -> None: ...

class EntryPost(_message.Message):
    __slots__ = ["description", "filter", "name", "policy", "priority"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    description: str
    filter: str
    name: str
    policy: str
    priority: int
    def __init__(self, name: _Optional[str] = ..., policy: _Optional[str] = ..., filter: _Optional[str] = ..., priority: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class EpsDisable_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class EpsEnable_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class EpsGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class EpsGet_Response(_message.Message):
    __slots__ = ["enabled", "eps", "error", "refresh_interval", "status"]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    EPS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    REFRESH_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    eps: int
    error: str
    refresh_interval: int
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., eps: _Optional[int] = ..., refresh_interval: _Optional[int] = ..., enabled: bool = ...) -> None: ...

class EpsUpdate_Request(_message.Message):
    __slots__ = ["eps", "refresh_interval"]
    EPS_FIELD_NUMBER: _ClassVar[int]
    REFRESH_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    eps: int
    refresh_interval: int
    def __init__(self, eps: _Optional[int] = ..., refresh_interval: _Optional[int] = ...) -> None: ...

class QueuePost_Request(_message.Message):
    __slots__ = ["wazuh_event"]
    WAZUH_EVENT_FIELD_NUMBER: _ClassVar[int]
    wazuh_event: str
    def __init__(self, wazuh_event: _Optional[str] = ...) -> None: ...

class RouteDelete_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class RouteGet_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class RouteGet_Response(_message.Message):
    __slots__ = ["error", "route", "status"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    error: str
    route: Entry
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., route: _Optional[_Union[Entry, _Mapping]] = ...) -> None: ...

class RoutePatchPriority_Request(_message.Message):
    __slots__ = ["name", "priority"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    name: str
    priority: int
    def __init__(self, name: _Optional[str] = ..., priority: _Optional[int] = ...) -> None: ...

class RoutePost_Request(_message.Message):
    __slots__ = ["route"]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    route: EntryPost
    def __init__(self, route: _Optional[_Union[EntryPost, _Mapping]] = ...) -> None: ...

class RouteReload_Request(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class TableGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class TableGet_Response(_message.Message):
    __slots__ = ["error", "status", "table"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TABLE_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    table: _containers.RepeatedCompositeFieldContainer[Entry]
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., table: _Optional[_Iterable[_Union[Entry, _Mapping]]] = ...) -> None: ...

class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Sync(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
