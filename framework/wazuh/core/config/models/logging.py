from pydantic import BaseModel, PositiveInt
from typing import Literal


class LoggingConfig(BaseModel):
    logging: Literal["info", "warning", "error", "debug", "debug2"] = "debug"


class LogFileMaxSizeConfig(BaseModel):
    enabled: bool = False
    size: PositiveInt = 1 #TODO(26356) - Handle M and K


class LoggingWithRotationConfig(BaseModel):
    logging: Literal["info", "warning", "error", "debug", "debug2"] = "debug"
    format: Literal["plain", "json", "both"] = "plain"
    max_size: LogFileMaxSizeConfig = LogFileMaxSizeConfig()

