"""An fsspec implementation backed by the native Pelican client library.

``pelicanfs_native`` wraps ``libpelicanclient`` (the C interface to the
Go Pelican client, from the pelican-c project) through CFFI and exposes
it as an fsspec filesystem.  It is a sibling of the pure-Python
``pelicanfs``, not a replacement: having two independent implementations
of one contract is what makes differential testing possible.
"""

from ._lib import (
    PelicanClientError,
    PelicanFileExistsError,
    PelicanFileNotFoundError,
    PelicanPermissionError,
    version,
)
from .core import OSDFNativeFileSystem, PelicanNativeFile, PelicanNativeFileSystem

__all__ = [
    "OSDFNativeFileSystem",
    "PelicanClientError",
    "PelicanFileExistsError",
    "PelicanFileNotFoundError",
    "PelicanNativeFile",
    "PelicanNativeFileSystem",
    "PelicanPermissionError",
    "version",
]
