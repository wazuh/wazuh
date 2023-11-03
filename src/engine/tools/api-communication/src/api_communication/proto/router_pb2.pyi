import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Entry(_message.Message):
    __slots__ = ["filter", "name", "policy", "policy_sync", "priority"]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    POLICY_SYNC_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    filter: str
    name: str
    policy: str
    policy_sync: str
    priority: int
    def __init__(self, name: _Optional[str] = ..., filter: _Optional[str] = ..., policy: _Optional[str] = ..., priority: _Optional[int] = ..., policy_sync: _Optional[str] = ...) -> None: ...

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

class RoutePatch_Request(_message.Message):
    __slots__ = ["route"]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    route: Entry
    def __init__(self, route: _Optional[_Union[Entry, _Mapping]] = ...) -> None: ...

class RoutePost_Request(_message.Message):
    __slots__ = ["route"]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    route: Entry
    def __init__(self, route: _Optional[_Union[Entry, _Mapping]] = ...) -> None: ...

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
