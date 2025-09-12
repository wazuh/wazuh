import engine_pb2 as _engine_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AssetCleanDeleted_Request(_message.Message):
    __slots__ = ["policy"]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: str
    def __init__(self, policy: _Optional[str] = ...) -> None: ...

class AssetCleanDeleted_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: str
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[str] = ...) -> None: ...

class AssetDelete_Request(_message.Message):
    __slots__ = ["asset", "namespace", "policy"]
    ASSET_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    asset: str
    namespace: str
    policy: str
    def __init__(self, policy: _Optional[str] = ..., asset: _Optional[str] = ..., namespace: _Optional[str] = ...) -> None: ...

class AssetDelete_Response(_message.Message):
    __slots__ = ["error", "status", "warning"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WARNING_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    warning: str
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., warning: _Optional[str] = ...) -> None: ...

class AssetGet_Request(_message.Message):
    __slots__ = ["namespace", "policy"]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    policy: str
    def __init__(self, policy: _Optional[str] = ..., namespace: _Optional[str] = ...) -> None: ...

class AssetGet_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedScalarFieldContainer[str]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[_Iterable[str]] = ...) -> None: ...

class AssetPost_Request(_message.Message):
    __slots__ = ["asset", "namespace", "policy"]
    ASSET_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    asset: str
    namespace: str
    policy: str
    def __init__(self, policy: _Optional[str] = ..., asset: _Optional[str] = ..., namespace: _Optional[str] = ...) -> None: ...

class AssetPost_Response(_message.Message):
    __slots__ = ["error", "status", "warning"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WARNING_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    warning: str
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., warning: _Optional[str] = ...) -> None: ...

class DefaultParentDelete_Request(_message.Message):
    __slots__ = ["namespace", "parent", "policy"]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    parent: str
    policy: str
    def __init__(self, policy: _Optional[str] = ..., namespace: _Optional[str] = ..., parent: _Optional[str] = ...) -> None: ...

class DefaultParentDelete_Response(_message.Message):
    __slots__ = ["error", "status", "warning"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WARNING_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    warning: str
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., warning: _Optional[str] = ...) -> None: ...

class DefaultParentGet_Request(_message.Message):
    __slots__ = ["namespace", "policy"]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    policy: str
    def __init__(self, policy: _Optional[str] = ..., namespace: _Optional[str] = ...) -> None: ...

class DefaultParentGet_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedScalarFieldContainer[str]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[_Iterable[str]] = ...) -> None: ...

class DefaultParentPost_Request(_message.Message):
    __slots__ = ["namespace", "parent", "policy"]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    parent: str
    policy: str
    def __init__(self, policy: _Optional[str] = ..., namespace: _Optional[str] = ..., parent: _Optional[str] = ...) -> None: ...

class DefaultParentPost_Response(_message.Message):
    __slots__ = ["error", "status", "warning"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WARNING_FIELD_NUMBER: _ClassVar[int]
    error: str
    status: _engine_pb2.ReturnStatus
    warning: str
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., warning: _Optional[str] = ...) -> None: ...

class NamespacesGet_Request(_message.Message):
    __slots__ = ["policy"]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: str
    def __init__(self, policy: _Optional[str] = ...) -> None: ...

class NamespacesGet_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedScalarFieldContainer[str]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[_Iterable[str]] = ...) -> None: ...

class PoliciesGet_Request(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class PoliciesGet_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedScalarFieldContainer[str]
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[_Iterable[str]] = ...) -> None: ...

class StoreDelete_Request(_message.Message):
    __slots__ = ["policy"]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: str
    def __init__(self, policy: _Optional[str] = ...) -> None: ...

class StoreGet_Request(_message.Message):
    __slots__ = ["namespaces", "policy"]
    NAMESPACES_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    namespaces: _containers.RepeatedScalarFieldContainer[str]
    policy: str
    def __init__(self, policy: _Optional[str] = ..., namespaces: _Optional[_Iterable[str]] = ...) -> None: ...

class StoreGet_Response(_message.Message):
    __slots__ = ["data", "error", "status"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: str
    error: str
    status: _engine_pb2.ReturnStatus
    def __init__(self, status: _Optional[_Union[_engine_pb2.ReturnStatus, str]] = ..., error: _Optional[str] = ..., data: _Optional[str] = ...) -> None: ...

class StorePost_Request(_message.Message):
    __slots__ = ["policy"]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: str
    def __init__(self, policy: _Optional[str] = ...) -> None: ...
