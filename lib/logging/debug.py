# lib/logging/logger_debug.py
import logging
import sys

# Configure logging for debug mode
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)

_logger = logging.getLogger('DNSlipstream')


def debug(fmt: str, *args):
    """Log debug message."""
    if args:
        _logger.debug(fmt, *args)
    else:
        _logger.debug(fmt)


def printf(fmt: str, *args):
    """Log info message."""
    if args:
        _logger.info(fmt, *args)
    else:
        _logger.info(fmt)


def fatal(*args):
    """Log fatal error and exit."""
    _logger.critical(' '.join(str(arg) for arg in args))
    sys.exit(1)


def fatalf(fmt: str, *args):
    """Log formatted fatal error and exit."""
    _logger.critical(fmt, *args)
    sys.exit(1)


def println(*v):
    """Log info message."""
    _logger.info(' '.join(str(arg) for arg in v))
