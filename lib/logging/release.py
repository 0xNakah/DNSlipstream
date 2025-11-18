# lib/logging/logger_production.py
import sys


def debug(fmt: str, *args):
    """No-op in production mode."""
    pass


def printf(fmt: str, *args):
    """No-op in production mode."""
    pass


def fatal(*args):
    """Exit without logging in production mode."""
    sys.exit(1)


def fatalf(fmt: str, *args):
    """Exit without logging in production mode."""
    sys.exit(1)


def println(*v):
    """No-op in production mode."""
    pass
