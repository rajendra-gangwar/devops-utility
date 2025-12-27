"""
Centralized logging setup and configuration.

Provides structured, colored logging for the certificate renewal process.
"""

import logging
import sys
from typing import Optional
from enum import IntEnum


class LogLevel(IntEnum):
    """Log level enumeration."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds colors to log output.

    Colors are only applied when output is to a terminal.
    """

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",      # Reset
        "BOLD": "\033[1m",       # Bold
    }

    def __init__(self, fmt: str = None, use_colors: bool = True):
        """
        Initialize the formatter.

        Args:
            fmt: Log message format string
            use_colors: Whether to use colors in output
        """
        super().__init__(fmt or "%(asctime)s [%(levelname)s] %(message)s")
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with optional colors.

        Args:
            record: Log record to format

        Returns:
            Formatted log message
        """
        # Save original values
        original_levelname = record.levelname
        original_msg = record.msg

        if self.use_colors:
            color = self.COLORS.get(record.levelname, "")
            reset = self.COLORS["RESET"]

            # Color the level name
            record.levelname = f"{color}{record.levelname}{reset}"

            # Color error/warning messages
            if original_levelname in ("ERROR", "CRITICAL"):
                record.msg = f"{color}{record.msg}{reset}"
            elif original_levelname == "WARNING":
                record.msg = f"{color}{record.msg}{reset}"

        # Format the message
        result = super().format(record)

        # Restore original values
        record.levelname = original_levelname
        record.msg = original_msg

        return result


class StructuredLogger(logging.Logger):
    """
    Extended logger with additional utility methods.
    """

    def __init__(self, name: str, level: int = logging.INFO):
        """
        Initialize the structured logger.

        Args:
            name: Logger name
            level: Minimum log level
        """
        super().__init__(name, level)

    def section(self, title: str) -> None:
        """
        Log a section header.

        Args:
            title: Section title
        """
        self.info("")
        self.info("=" * 60)
        self.info(title)
        self.info("=" * 60)

    def subsection(self, title: str) -> None:
        """
        Log a subsection header.

        Args:
            title: Subsection title
        """
        self.info("")
        self.info(f"--- {title} ---")

    def success(self, message: str) -> None:
        """
        Log a success message (INFO level with special formatting).

        Args:
            message: Success message
        """
        self.info(f"[OK] {message}")

    def failure(self, message: str) -> None:
        """
        Log a failure message (ERROR level with special formatting).

        Args:
            message: Failure message
        """
        self.error(f"[FAIL] {message}")


# Global logger instance
_logger: Optional[StructuredLogger] = None


def setup_logger(
    name: str = "CertRenewal",
    verbose: bool = False,
    use_colors: bool = True,
    log_file: Optional[str] = None,
) -> StructuredLogger:
    """
    Setup and configure the global logger.

    Args:
        name: Logger name
        verbose: Enable debug-level logging
        use_colors: Enable colored output
        log_file: Optional file path for log output

    Returns:
        Configured StructuredLogger instance
    """
    global _logger

    # Create logger
    logging.setLoggerClass(StructuredLogger)
    logger = logging.getLogger(name)
    logger.__class__ = StructuredLogger

    # Set level
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter(use_colors=use_colors))
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        ))
        logger.addHandler(file_handler)

    _logger = logger
    return logger


def get_logger() -> StructuredLogger:
    """
    Get the global logger instance.

    Returns:
        The configured StructuredLogger instance

    Raises:
        RuntimeError: If logger has not been set up
    """
    global _logger

    if _logger is None:
        # Create default logger
        _logger = setup_logger()

    return _logger
