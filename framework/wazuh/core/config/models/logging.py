from pydantic import BaseModel
from typing import Literal, List


class LoggingConfig(BaseModel):
    level: Literal["info", "warning", "error", "debug", "debug2"] = "debug"


class LogFileMaxSizeConfig(BaseModel):
    enabled: bool = False
    size: str = "1M" #TODO(26356) - Handle M and K pattern


class LoggingWithRotationConfig(BaseModel):
    level: Literal["info", "warning", "error", "debug", "debug2"] = "debug"
    format: List[Literal["plain", "json"]] = ["plain"]
    max_size: LogFileMaxSizeConfig = LogFileMaxSizeConfig()
