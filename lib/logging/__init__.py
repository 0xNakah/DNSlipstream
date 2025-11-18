# lib/logging/__init__.py
import os

DEBUG_MODE = os.getenv('DEBUG', '').lower() in ('true', '1', 'yes')

if DEBUG_MODE:
    from .debug import debug, printf, fatal, fatalf, println
else:
    from .release import debug, printf, fatal, fatalf, println

__all__ = ['debug', 'printf', 'fatal', 'fatalf', 'println']
