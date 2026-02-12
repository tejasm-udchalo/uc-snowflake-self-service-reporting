# Enhanced logging utilities for Streamlit app
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Create logs directory
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def setup_logging(name: str = "streamlit_app", level: int = logging.INFO) -> logging.Logger:
    """
    Set up structured logging with console and file handlers.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger
    
    logger.setLevel(level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (daily rotation)
    log_file = LOGS_DIR / f"{datetime.now():%Y-%m-%d}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


def log_query_execution(
    logger: logging.Logger,
    username: str,
    report_name: str,
    execution_time_sec: float,
    rows_returned: int,
    success: bool
) -> None:
    """
    Log query execution with structured data.
    
    Args:
        logger: Logger instance
        username: User executing query
        report_name: Name of report
        execution_time_sec: Query execution time
        rows_returned: Number of rows returned
        success: Whether query succeeded
    """
    status = "✅ SUCCESS" if success else "❌ FAILED"
    logger.info(
        f"{status} | User: {username} | Report: {report_name} | "
        f"Time: {execution_time_sec:.2f}s | Rows: {rows_returned}"
    )


def log_error_context(
    logger: logging.Logger,
    username: str,
    operation: str,
    error: Exception,
    context: Optional[dict] = None
) -> None:
    """
    Log error with full context for debugging.
    
    Args:
        logger: Logger instance
        username: User who triggered error
        operation: Operation being performed
        error: Exception instance
        context: Additional context dict
    """
    context_str = " | ".join([f"{k}={v}" for k, v in (context or {}).items()])
    logger.error(
        f"User: {username} | Operation: {operation} | Error: {error} | Context: {context_str}",
        exc_info=True
    )


# Default logger instance
logger = setup_logging()

__all__ = ["setup_logging", "log_query_execution", "log_error_context", "logger"]
