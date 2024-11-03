from pydantic import BaseModel
from typing import Literal, List


class LoggingConfig(BaseModel):
    level: Literal["info", "debug", "debug2"] = "debug"

    def get_level_value(self) -> int:
        if self.level == "info":
            return 0
        elif self.level == "debug":
            return 1
        else:
            return 2


class LogFileMaxSizeConfig(BaseModel):
    enabled: bool = False
    size: str = "1M" #TODO(26356) - Handle M and K pattern


class LoggingWithRotationConfig(BaseModel):
    level: Literal["info", "warning", "error", "debug", "debug2"] = "debug"
    format: List[Literal["plain", "json"]] = ["plain"]
    max_size: LogFileMaxSizeConfig = LogFileMaxSizeConfig()
