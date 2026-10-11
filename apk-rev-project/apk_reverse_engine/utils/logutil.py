#!/usr/bin/env python3
"""Project-wide logging utility

Provides a consistent logging interface across all modules.
Use get_logger(__name__) to obtain a module-specific logger.
"""
import logging
import os
import sys

_configured = False

def _configure():
    global _configured
    if _configured:
        return
    level = os.environ.get('RENG_LOG_LEVEL', 'WARNING').upper()
    fmt = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(fmt)
    root = logging.getLogger('apk_reverse_engine')
    root.setLevel(level)
    root.addHandler(handler)
    _configured = True

def get_logger(name=None):
    """Get a logger under the project namespace."""
    _configure()
    if name and not name.startswith('apk_reverse_engine'):
        name = f'apk_reverse_engine.{name}'
    return logging.getLogger(name or 'apk_reverse_engine')
