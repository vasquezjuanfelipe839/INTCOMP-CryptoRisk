"""Multi-format inventory importers. Maps external files to Core-compatible rows.

Does not invent required field values. Does not touch Core engines.
"""
from .pipeline import parse_inventory_file, MAX_UPLOAD_BYTES

__all__ = ["parse_inventory_file", "MAX_UPLOAD_BYTES"]
