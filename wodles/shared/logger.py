from abc import ABC, abstractmethod
import logging
import sys


class LogStrategy(ABC):
    """
    LogStrategy interface.
    Defines the methods that need to be implemented by the concrete classes
    (GCP, AWS, and Azure) for logging.
    """

    @abstractmethod
    def info(self, message: str):
        """
        Log an INFO level message.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def debug(self, message: str):
        """
        Log a DEBUG level message.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def warning(self, message: str):
        """
        Log a WARNING level message.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass

    @abstractmethod
    def error(self, message: str):
        """
        Log an ERROR level message.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        pass


class Logger:
    """
    Logger class.
    Provides a flexible logging solution for Wazuh that supports
    GCP, AWS, and Azure integrations using the strategy pattern.
    """

    def __init__(self, strategy: LogStrategy, logger_name: str, log_level=1):
        """
        Initialize the Logger class.
        Parameters
        ----------
        strategy : LogStrategy
            The logging strategy to be used (GCP, AWS, or Azure).
        logger_name : str
            The name of the logger.
        log_level : int, optional
            The logging level (0 for WARNING, 1 for INFO, 2 for DEBUG), default is 1.
        """
        self.strategy = strategy
        self.logger = self.setup_logger(logger_name, log_level)

    def setup_logger(self, logger_name: str, log_level: int) -> logging.Logger:
        """
        Set up the logger.
        Parameters
        ----------
        logger_name : str
            The name of the logger.
        log_level : int
            The logging level (0 for WARNING, 1 for INFO, 2 for DEBUG).
        Returns
        -------
        logging.Logger
            Configured logger instance.
        """
        logger = logging.getLogger(logger_name)
        log_levels = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}
        logger.setLevel(log_levels.get(log_level, logging.INFO))
        handler = self._setup_handler()
        logger.addHandler(handler)
        return logger

    def _setup_handler(self) -> logging.Handler:
        """
        Set up the handler for the logger.
        Returns
        -------
        logging.Handler
            Configured handler instance.
        """
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
        return handler

    def info(self, message: str):
        """
        Log an INFO level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.info(message)

    def debug(self, message: str):
        """
        Log a DEBUG level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.debug(message)

    def warning(self, message: str):
        """
        Log a WARNING level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.warning(message)

    def error(self, message: str):
        """
        Log an ERROR level message using the selected strategy.
        Parameters
        ----------
        message : str
            The message to be logged.
        """
        self.strategy.error(message)