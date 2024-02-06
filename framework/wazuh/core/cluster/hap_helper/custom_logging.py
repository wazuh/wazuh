import calendar
import gzip
import logging
import re
import shutil
from copy import copy
from glob import glob
from logging.handlers import TimedRotatingFileHandler
from os import chmod, unlink, path, makedirs


class CustomFileRotatingHandler(TimedRotatingFileHandler):
    def doRollover(self):
        logging.handlers.TimedRotatingFileHandler.doRollover(self)

        rotated_file = glob(f'{self.baseFilename}.*')[0]

        new_rotated_file = self.compute_archives_directory(rotated_file)
        with open(rotated_file, 'rb') as f_in, gzip.open(new_rotated_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        chmod(new_rotated_file, 0o640)
        unlink(rotated_file)

    def compute_archives_directory(self, rotated_filepath):
        rotated_file = path.basename(rotated_filepath)
        year, month, day = re.match(r'[\w.-]+\.(\d+)-(\d+)-(\d+)', rotated_file).groups()
        month = calendar.month_abbr[int(month)]
        log_path = path.join(path.splitext(self.baseFilename)[0], year, month)
        if not path.exists(log_path):
            makedirs(log_path)

        return f'{log_path}/{path.basename(self.baseFilename)}-{day}.gz'


class LoggingFilter(logging.Filter):
    def __init__(self, module_name: str):
        super().__init__()
        self.module_name = module_name

    def filter(self, record) -> bool:
        record.levelname = f'{record.levelname}:'
        record.module_name = f'[{self.module_name}]'
        return True


class ColoredFormatter(logging.Formatter):
    GREY = '\x1b[38;20m'
    YELLOW = '\x1b[33;20m'
    RED = '\x1b[31;20m'
    BOLD_RED = '\x1b[31;1m'
    ORANGE = '\x1b[33m;20m'
    DARK_BLUE = '\x1b[34m'
    GREY_BLUE = '\x1b[36m'
    RESET = '\x1b[0m'

    TRACE_LEVEL = 5

    def __init__(self, fmt, style='%', datefmt='', *args, **kwargs):
        super().__init__(fmt, *args, **kwargs)
        self.style = style
        self.datefmt = datefmt

        self.FORMATS = {
            logging.DEBUG: self.DARK_BLUE + fmt + self.RESET,
            logging.INFO: self.GREY + fmt + self.RESET,
            logging.WARNING: self.YELLOW + fmt + self.RESET,
            logging.ERROR: self.RED + fmt + self.RESET,
            logging.CRITICAL: self.BOLD_RED + fmt + self.RESET,
            self.TRACE_LEVEL: self.GREY_BLUE + fmt + self.RESET,
        }

    def format(self, record):
        record_copy = copy(record)
        log_fmt = self.FORMATS.get(record_copy.levelno)
        formatter = logging.Formatter(log_fmt, style=self.style, datefmt=self.datefmt)
        return formatter.format(record_copy)


class CustomLogger:
    TRACE_LEVEL = 5

    def __init__(self, name: str, file_path: str = '', tag: str = 'Main', level: int = logging.INFO):
        logging.addLevelName(self.TRACE_LEVEL, 'TRACE')
        logger = logging.getLogger(name)
        logger.trace = self.trace
        logger.addFilter(LoggingFilter(tag))
        logger.propagate = False

        colored_formatter = ColoredFormatter(
            '%(asctime)s %(levelname)-9s %(module_name)-11s %(message)s', style='%', datefmt='%Y/%m/%d %H:%M:%S'
        )
        colored_handler = logging.StreamHandler()
        colored_handler.setFormatter(colored_formatter)

        if file_path:
            logger_formatter = logging.Formatter(
                '%(asctime)s %(levelname)-9s %(module_name)-11s %(message)s', style='%', datefmt='%Y/%m/%d %H:%M:%S'
            )
            fh = CustomFileRotatingHandler(filename=file_path, when='midnight')
            fh.setFormatter(logger_formatter)
            logger.addHandler(fh)

        logger.addHandler(colored_handler)
        logger.setLevel(level)

        self.logger = logger

    def get_logger(self) -> logging.Logger:
        return self.logger

    def trace(self, message, *args, **kwargs):
        if self.logger.isEnabledFor(self.TRACE_LEVEL):
            self.logger._log(self.TRACE_LEVEL, message, args, **kwargs)
