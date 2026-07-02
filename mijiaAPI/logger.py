import logging
import os
import sys


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;31m",
        "RESET": "\033[0m",
    }

    def __init__(self, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt, datefmt, style)
        no_color = (
            os.environ.get("NO_COLOR", "")
            or os.environ.get("MIJIA_NO_COLOR", "")
        )
        self.use_colors = sys.stdout.isatty() and not no_color

    def format(self, record):
        log_message = super().format(record)
        if self.use_colors:
            color_code = self.COLORS.get(record.levelname, self.COLORS["RESET"])
            return f"{color_code}{log_message}{self.COLORS['RESET']}"
        return log_message

def get_logger(name: str) -> logging.Logger:
    """
    获取指定名称的日志记录器。

    Args:
        name (str): 日志记录器的名称。

    Returns:
        logging.Logger: 日志记录器对象。
    """
    logger = logging.getLogger(name)

    console_handler = logging.StreamHandler()

    formatter = ColorFormatter(
        "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    return logger

logger = get_logger("mijiaAPI")
logger.setLevel(logging.INFO)
