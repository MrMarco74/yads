"""
YADS Release Automation Library

This package provides tools for automating the YADS release process,
including version management, changelog generation, translation, and deployment.
"""

__version__ = "2.1.0"

from .version import SemanticVersion
from .config import ReleaseConfig
from .changelog import ChangelogManager
from .updater import FileUpdater
from .translator import ChangelogTranslator
from .uploader import ReleaseUploader

__all__ = [
    "SemanticVersion",
    "ReleaseConfig",
    "ChangelogManager",
    "FileUpdater",
    "ChangelogTranslator",
    "ReleaseUploader",
]
