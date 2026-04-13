"""
nids/storage/__init__.py
Storage package exports
"""

from nids.storage.database import Database, get_database

__all__ = ["Database", "get_database"]
