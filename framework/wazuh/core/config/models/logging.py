import logging

from pydantic import BaseModel, Field
from typing import Literal, List


class LoggingConfig(BaseModel):
    """Configuration for logging levels.

    Parameters
    ----------
    level : Literal["info", "debug", "debug2"]
        The logging level. Default is "info".
    """
    level: Literal["info", "debug", "debug2"] = "info"

    def get_level_value(self) -> int:
        """Returns the integer value associated with the logging level.

        Returns
        -------
        int
            The integer value corresponding to the logging level:
            - 0 for "info"
            - 1 for "debug"
            - 2 for "debug2"
        """
        if self.level == "info":
            return 0
        elif self.level == "debug":
            return 1
        else:
            return 2


class LogFileMaxSizeConfig(BaseModel):
    """Configuration for maximum log file size.

    Parameters
    ----------
    enabled : bool
        Whether the maximum file size feature is enabled. Default is False.
    size : str
        The maximum size of the log file. Supports 'M' for megabytes and 'K' for kilobytes. Default is "1M".
    """
    enabled: bool = False
    size: str = Field(default="1M", pattern=r"(\d+)([KM])")


class LoggingWithRotationConfig(BaseModel):
    """Configuration for logging with rotation.

     Parameters
     ----------
     level : Literal["debug", "info", "warning", "error", "critical"]
         The logging level. Default is "debug".
     format : List[Literal["plain", "json"]]
         The format for logging output. Default is ["plain"].
     max_size : LogFileMaxSizeConfig
         Configuration for the maximum log file size. Default is an instance of LogFileMaxSizeConfig.
    """
    level: Literal["debug", "info", "warning", "error", "critical"] = "debug"
    format: List[Literal["plain", "json"]] = ["plain"]
    max_size: LogFileMaxSizeConfig = LogFileMaxSizeConfig()

    def get_level(self) -> int:
        """Returns the integer value corresponding to the logging level.

        Returns
        -------
        int
            The integer value corresponding to the logging level:
            - logging.DEBUG for "debug"
            - logging.INFO for "info"
            - logging.WARNING for "warning"
            - logging.ERROR for "error"
            - logging.CRITICAL for "critical"
        """
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
