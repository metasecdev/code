"""
Cyber Intelligence Gateway (CIG)
Main application package
"""

__version__ = "1.0.0"
__author__ = "CIG Security Team"

from app.core.config import Settings
from app.core.engine import CIGEngine

__all__ = ["Settings", "CIGEngine"]
