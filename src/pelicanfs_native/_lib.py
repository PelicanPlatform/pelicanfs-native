"""Low-level glue over libpelicanclient.

Nothing here knows about fsspec; this module owns the C lifetime rules
(who frees what), the one-shot process-wide initialization, and the
translation of Pelican error codes into Python exceptions.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from ._pelican_cffi import ffi, lib

__all__ = [
    "O_CREATE",
    "O_RDONLY",
    "O_RDWR",
    "O_WRONLY",
    "PelicanClientError",
    "check",
    "configure",
    "initialize",
    "is_initialized",
    "transfer_opts",
    "version",
]

O_RDONLY = lib.PELICAN_O_RDONLY
O_WRONLY = lib.PELICAN_O_WRONLY
O_RDWR = lib.PELICAN_O_RDWR
O_CREATE = lib.PELICAN_O_CREATE

# Codes from the Pelican error taxonomy (docs/error_codes.yaml upstream).
# Only the ones with a meaningful Python counterpart are listed; anything
# else becomes a plain PelicanClientError.
_CODE_PARAMETER = 1000
_CODE_PARAMETER_FILE_NOT_FOUND = 1011
_CODE_RESOLUTION = 4000
_CODE_TOKEN_NOT_FOUND = 4010
_CODE_SPECIFICATION_FILE_NOT_CREATED = 5002
_CODE_SPECIFICATION_FILE_NOT_FOUND = 5011
_CODE_SPECIFICATION_FILE_EXISTS = 5012


class PelicanClientError(OSError):
    """An error raised by the native Pelican client.

    Subclasses :class:`OSError` so that callers who only catch the
    standard filesystem exceptions still see Pelican failures.
    """

    def __init__(self, message: str, *, code: int = 0, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base} [pelican error {self.code}]" if self.code else base


class PelicanFileNotFoundError(PelicanClientError, FileNotFoundError):
    pass


class PelicanFileExistsError(PelicanClientError, FileExistsError):
    pass


class PelicanPermissionError(PelicanClientError, PermissionError):
    pass


_EXCEPTION_BY_CODE: Mapping[int, type[PelicanClientError]] = {
    _CODE_PARAMETER_FILE_NOT_FOUND: PelicanFileNotFoundError,
    _CODE_SPECIFICATION_FILE_NOT_FOUND: PelicanFileNotFoundError,
    _CODE_SPECIFICATION_FILE_EXISTS: PelicanFileExistsError,
    _CODE_RESOLUTION: PelicanPermissionError,
    _CODE_TOKEN_NOT_FOUND: PelicanPermissionError,
}


def _message(err: Any) -> str:
    raw = lib.pelican_error_message(err)
    if raw == ffi.NULL:
        return "unknown error"
    return ffi.string(raw).decode("utf-8", "replace")


def _build_exception(err: Any) -> PelicanClientError:
    """Build a Python exception from a *borrowed* pelican_error."""
    code = lib.pelican_error_code(err)
    retryable = bool(lib.pelican_error_is_retryable(err))
    message = _message(err)
    cls = _EXCEPTION_BY_CODE.get(code)
    if cls is None:
        # 5000-series failures that carry no more specific code still
        # mean "the server gave a definitive answer about this object",
        # which for a filesystem is overwhelmingly a missing file.
        if code == _CODE_SPECIFICATION_FILE_NOT_CREATED:
            cls = PelicanClientError
        elif 5000 <= code < 6000:
            cls = PelicanFileNotFoundError
        elif code == _CODE_PARAMETER:
            cls = PelicanClientError
        else:
            cls = PelicanClientError
    return cls(message, code=code, retryable=retryable)


def check(err: Any) -> None:
    """Raise if ``err`` is a non-NULL *owned* pelican_error, then free it."""
    if err == ffi.NULL:
        return
    try:
        exc = _build_exception(err)
    finally:
        lib.pelican_error_free(err)
    raise exc


def borrowed_error(err: Any) -> PelicanClientError | None:
    """Translate a borrowed pelican_error (from a result) without freeing."""
    if err == ffi.NULL:
        return None
    return _build_exception(err)


# --------------------------------------------------------------------- #
# Process-wide initialization                                           #
# --------------------------------------------------------------------- #
#
# pelican_client_init may be called once per process and config_set must
# precede it, so configuration is a property of the process rather than
# of a filesystem instance.  Rather than let a second, differently
# configured filesystem silently inherit the first one's settings, a
# conflicting request raises -- a silent mismatch would be invisible and
# would quietly invalidate any differential comparison.

_lock = threading.Lock()
_initialized = False
_applied: dict[str, str] = {}
_config_file: str | None = None


def is_initialized() -> bool:
    return _initialized


def version() -> str:
    return ffi.string(lib.pelican_version()).decode("utf-8", "replace")


def configure(settings: Mapping[str, str]) -> None:
    """Apply Pelican configuration parameters before initialization.

    Re-applying a value identical to one already set is a no-op, so
    constructing several filesystems with the same settings is fine.
    """
    with _lock:
        _configure_locked(settings)


def _configure_locked(settings: Mapping[str, str]) -> None:
    for key, value in settings.items():
        value = str(value)
        previous = _applied.get(key)
        if previous == value:
            continue
        if _initialized or previous is not None:
            raise PelicanClientError(
                f"cannot set Pelican configuration {key!r} to {value!r}: the "
                f"native client is process-global and is already configured "
                f"with {previous!r}. Start a fresh process to use a different "
                f"configuration."
            )
        check(lib.pelican_config_set(key.encode(), value.encode()))
        _applied[key] = value


def initialize(
    config_file: str | None = None,
    settings: Mapping[str, str] | None = None,
) -> None:
    """Initialize the native client, at most once per process."""
    global _initialized, _config_file
    with _lock:
        if _initialized:
            if settings:
                _configure_locked(settings)
            if config_file is not None and config_file != _config_file:
                raise PelicanClientError(
                    f"the native client is already initialized with config file "
                    f"{_config_file!r}; cannot reinitialize with {config_file!r}"
                )
            return
        if settings:
            _configure_locked(settings)
        arg = ffi.NULL if config_file is None else config_file.encode()
        check(lib.pelican_client_init(arg))
        _initialized = True
        _config_file = config_file


# --------------------------------------------------------------------- #
# Handles                                                               #
# --------------------------------------------------------------------- #


@contextmanager
def transfer_opts(
    token: str | None = None,
    token_location: str | None = None,
    recursive: bool = False,
    caches: list[str] | None = None,
) -> Iterator[Any]:
    """A scoped pelican_transfer_opts."""
    opts = lib.pelican_transfer_opts_new()
    if opts == ffi.NULL:
        raise PelicanClientError("failed to allocate transfer options")
    try:
        if token:
            lib.pelican_transfer_opts_set_token(opts, token.encode())
        if token_location:
            lib.pelican_transfer_opts_set_token_location(opts, token_location.encode())
        if recursive:
            lib.pelican_transfer_opts_set_recursive(opts, 1)
        for cache in caches or ():
            lib.pelican_transfer_opts_add_cache(opts, cache.encode())
        yield opts
    finally:
        lib.pelican_transfer_opts_free(opts)


@contextmanager
def file_info_ptr() -> Iterator[Any]:
    """An out-parameter for pelican_file_info*, freed on exit."""
    out = ffi.new("pelican_file_info **")
    try:
        yield out
    finally:
        if out[0] != ffi.NULL:
            lib.pelican_file_info_free(out[0])


@contextmanager
def file_info_list_ptr() -> Iterator[Any]:
    """An out-parameter for pelican_file_info_list*, freed on exit."""
    out = ffi.new("pelican_file_info_list **")
    try:
        yield out
    finally:
        if out[0] != ffi.NULL:
            lib.pelican_file_info_list_free(out[0])


def info_as_dict(info: Any) -> dict[str, Any]:
    """Copy a pelican_file_info into plain Python values."""
    name = lib.pelican_file_info_name(info)
    return {
        "name": "" if name == ffi.NULL else ffi.string(name).decode("utf-8", "replace"),
        "size": int(lib.pelican_file_info_size(info)),
        "mtime": int(lib.pelican_file_info_mtime(info)),
        "is_collection": bool(lib.pelican_file_info_is_collection(info)),
    }
