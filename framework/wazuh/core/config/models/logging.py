import logging

from pydantic import BaseModel
from typing import Literal, List


class LoggingConfig(BaseModel):
    level: Literal["info", "debug", "debug2"] = "info"

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
    level: Literal["debug", "info", "warning", "error", "critical"] = "debug"
    format: List[Literal["plain", "json"]] = ["plain"]
    max_size: LogFileMaxSizeConfig = LogFileMaxSizeConfig()

    def get_level(self) -> int:
        if self.level == "debug":
            return logging.DEBUG
        elif self.level == "info":
            return logging.INFO
        elif self.level == "warning":
            return logging.WARNING
        elif self.level == "error":
            return logging.ERROR
        elif self.level == "critical":
            return logging.CRITICAL
        else:
            return logging.ERROR
