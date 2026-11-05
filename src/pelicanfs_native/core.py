"""An fsspec filesystem backed by the native Pelican client.

This is a second, independent implementation of the same contract that
``pelicanfs`` implements in pure Python.  Where ``pelicanfs`` speaks to
the director and caches itself over aiohttp, everything here is handled
by the Go client inside ``libpelicanclient`` -- director interaction,
cache selection, token discovery, retries and redirects.

The two are deliberately *not* written to agree.  Each implements the
fsspec contract as directly as it can; comparing them is the point, and
a divergence is a finding rather than something to paper over in the
library.  Normalization for comparison belongs in the harness.
"""

from __future__ import annotations

import os
import tempfile
import urllib.parse
from typing import Any

from fsspec.spec import AbstractBufferedFile, AbstractFileSystem

from . import _lib
from ._lib import PelicanClientError, PelicanFileNotFoundError
from ._pelican_cffi import ffi, lib

__all__ = [
    "OSDFNativeFileSystem",
    "PelicanNativeFile",
    "PelicanNativeFileSystem",
]

_SCHEMES = ("pelican+native", "osdf+native", "pelican", "osdf")
_OSDF_DISCOVERY = "pelican://osg-htc.org"


def _split_url(path: str) -> tuple[str | None, str]:
    """Split a Pelican-ish path into (discovery URL, namespace path).

    Accepts ``pelican://host/ns/obj``, the ``+native`` scheme variants,
    ``osdf:///ns/obj``, and a bare ``/ns/obj`` (no federation implied).
    """
    parsed = urllib.parse.urlparse(path)
    scheme = parsed.scheme.lower()

    if scheme in ("osdf", "osdf+native"):
        # osdf:///ns/obj parses with an empty netloc; osdf://ns/obj is the
        # common sloppy form, where the "host" is really the first path
        # component.
        ns = parsed.path if not parsed.netloc else f"/{parsed.netloc}{parsed.path}"
        return _OSDF_DISCOVERY, ns or "/"
    if scheme in ("pelican", "pelican+native"):
        if not parsed.netloc:
            raise ValueError(f"{path!r} names no federation host")
        return f"pelican://{parsed.netloc}", parsed.path or "/"
    if scheme:
        raise ValueError(
            f"unsupported scheme {parsed.scheme!r}: only pelican:// and osdf:// "
            f"(and their +native aliases) name Pelican objects"
        )
    if path.startswith("/"):
        return None, path
    # A schemeless, relative path whose first component is the federation
    # host -- the form some libraries (xarray among them) hand to fsspec.
    parsed = urllib.parse.urlparse(f"pelican://{path}")
    return f"pelican://{parsed.netloc}", parsed.path or "/"


class PelicanNativeFileSystem(AbstractFileSystem):
    """Access a Pelican federation through ``libpelicanclient``.

    One instance is bound to one federation, named by
    ``federation_discovery_url``.  Paths may be given as full
    ``pelican://`` URLs or as bare namespace paths; a URL naming a
    different federation than the instance is an error, because an
    fsspec instance addresses exactly one backend.
    """

    protocol = ("pelican+native", "osdf+native")
    root_marker = "/"
    sep = "/"

    # The Go runtime behind this filesystem is initialized once per
    # process and cannot be reconfigured or forked.  fsspec's instance
    # cache would hand a cached instance to a differently configured
    # caller and hide that; keep every construction explicit.
    cachable = False

    def __init__(
        self,
        federation_discovery_url: str = "",
        token: str | None = None,
        token_location: str | None = None,
        preferred_caches: list[str] | None = None,
        config_file: str | None = None,
        client_config: dict[str, str] | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        if federation_discovery_url:
            disco, _ = _split_url(
                federation_discovery_url
                if "://" in federation_discovery_url
                else f"pelican://{federation_discovery_url}"
            )
            self.discovery_url = (disco or "").rstrip("/")
        else:
            self.discovery_url = ""
        self.token = token
        self.token_location = token_location
        self.preferred_caches = list(preferred_caches or [])

        _lib.initialize(config_file=config_file, settings=client_config)

    # ---------------------------------------------------------------- #
    # Path handling                                                    #
    # ---------------------------------------------------------------- #

    @classmethod
    def _strip_protocol(cls, path: str | list[str]) -> Any:
        """Reduce a path to the namespace path the federation knows.

        Unlike pelicanfs, which keeps ``host/path`` here, this returns a
        rooted namespace path.  The federation is instance state (see
        ``_get_kwargs_from_urls``), so carrying the host in every path
        would mean two names for one object.
        """
        if isinstance(path, (list, tuple)):
            return [cls._strip_protocol(p) for p in path]
        if path in ("", cls.root_marker):
            return cls.root_marker
        _, ns = _split_url(path)
        ns = ns.rstrip("/") or cls.root_marker
        return ns if ns.startswith("/") else "/" + ns

    @staticmethod
    def _get_kwargs_from_urls(path: str) -> dict[str, str]:
        """Let ``fsspec.open("pelican+native://host/x")`` bind the federation."""
        try:
            disco, _ = _split_url(path)
        except ValueError:
            return {}
        return {"federation_discovery_url": disco} if disco else {}

    def _url(self, path: str) -> str:
        """Build the absolute Pelican URL the C library expects."""
        disco, ns = _split_url(path) if ("://" in path or not path.startswith("/")) else (None, path)
        if disco and self.discovery_url and disco.rstrip("/") != self.discovery_url:
            raise ValueError(
                f"{path!r} names federation {disco!r}, but this filesystem is "
                f"bound to {self.discovery_url!r}. Construct a separate "
                f"filesystem for another federation."
            )
        base = (disco or self.discovery_url).rstrip("/")
        if not base:
            raise ValueError(
                f"cannot resolve {path!r}: no federation discovery URL was given "
                f"to this filesystem and the path does not name one"
            )
        if not ns.startswith("/"):
            ns = "/" + ns
        return base + urllib.parse.quote(ns, safe="/@:+$,;=~!*'()&")

    def _opts(self, recursive: bool = False) -> Any:
        return _lib.transfer_opts(
            token=self.token,
            token_location=self.token_location,
            recursive=recursive,
            caches=self.preferred_caches,
        )

    # ---------------------------------------------------------------- #
    # Metadata                                                         #
    # ---------------------------------------------------------------- #

    def _entry(self, raw: dict[str, Any], name: str) -> dict[str, Any]:
        """Convert a pelican_file_info into an fsspec entry.

        The caller supplies the name.  The underlying library does not
        report one consistently -- a stat echoes the *resolved endpoint*
        path it was answered from, such as
        ``/api/v1.0/origin/data/ns/obj``, while a listing reports
        namespace paths -- and fsspec requires a name that addresses the
        object in this filesystem.  Deriving it from what the caller
        asked for is the only shape that always satisfies that.
        """
        return {
            "name": name.rstrip("/") or self.root_marker,
            "size": raw["size"],
            "type": "directory" if raw["is_collection"] else "file",
            "mtime": raw["mtime"],
        }

    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        # Resolve the URL first: _strip_protocol is a classmethod and
        # discards the host, so a foreign federation has to be caught
        # while the original spelling is still intact.
        url = self._url(path)
        path = self._strip_protocol(path)
        with self._opts() as opts, _lib.file_info_ptr() as out:
            _lib.check(lib.pelican_stat(ffi.NULL, url.encode(), opts, out))
            if out[0] == ffi.NULL:
                raise PelicanFileNotFoundError(path)
            return self._entry(_lib.info_as_dict(out[0]), path)

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[Any]:
        url = self._url(path)
        path = self._strip_protocol(path)
        with self._opts() as opts, _lib.file_info_list_ptr() as out:
            _lib.check(lib.pelican_list(ffi.NULL, url.encode(), opts, out))
            if out[0] == ffi.NULL:
                return []
            count = lib.pelican_file_info_list_count(out[0])
            entries = []
            base = path.rstrip("/")
            for i in range(count):
                item = lib.pelican_file_info_list_get(out[0], i)
                if item == ffi.NULL:
                    continue
                raw = _lib.info_as_dict(item)
                child = raw["name"].rstrip("/").rsplit("/", 1)[-1]
                entries.append(self._entry(raw, f"{base}/{child}" if child else base))
        # A listing that echoes the collection itself would make `find`
        # and `walk` recurse forever.
        entries = [e for e in entries if e["name"].rstrip("/") != path.rstrip("/")]
        entries.sort(key=lambda e: e["name"])
        if detail:
            return entries
        return [e["name"] for e in entries]

    def created(self, path: str) -> Any:
        raise NotImplementedError("Pelican does not report object creation times")

    def modified(self, path: str) -> Any:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(self.info(path)["mtime"], tz=timezone.utc)

    # ---------------------------------------------------------------- #
    # Reads                                                            #
    # ---------------------------------------------------------------- #

    def cat_file(
        self, path: str, start: int | None = None, end: int | None = None, **kwargs: Any
    ) -> bytes:
        self._url(path)  # validates the federation before the host is lost
        path = self._strip_protocol(path)
        with self._handle(path, _lib.O_RDONLY) as handle:
            if start is None and end is None:
                return _read_all(handle)
            size = None
            if (start is not None and start < 0) or (end is not None and end < 0):
                size = self.info(path)["size"]
            offset = 0 if start is None else (start if start >= 0 else max(size + start, 0))
            if end is None:
                stop = None
            else:
                stop = end if end >= 0 else size + end
            if stop is None:
                return _read_all(handle, offset=offset)
            length = max(stop - offset, 0)
            return _pread(handle, offset, length)

    def _open(
        self,
        path: str,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AbstractBufferedFile:
        return PelicanNativeFile(
            self,
            path,
            mode=mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_options=cache_options,
            **kwargs,
        )

    def get_file(self, rpath: str, lpath: str, **kwargs: Any) -> None:
        if os.path.isdir(lpath):
            return
        url = self._url(rpath)
        rpath = self._strip_protocol(rpath)
        with self._opts(recursive=bool(kwargs.get("recursive"))) as opts:
            _lib.check(
                lib.pelican_get(ffi.NULL, url.encode(), str(lpath).encode(), opts, ffi.NULL)
            )

    # ---------------------------------------------------------------- #
    # Writes                                                           #
    # ---------------------------------------------------------------- #

    def put_file(self, lpath: str, rpath: str, **kwargs: Any) -> None:
        url = self._url(rpath)
        rpath = self._strip_protocol(rpath)
        with self._opts(recursive=bool(kwargs.get("recursive"))) as opts:
            _lib.check(
                lib.pelican_put(ffi.NULL, str(lpath).encode(), url.encode(), opts, ffi.NULL)
            )

    def pipe_file(self, path: str, value: bytes, **kwargs: Any) -> None:
        # Stage through a temporary file rather than the streaming write
        # handle: an upload is finalized by close, and a failure there
        # must surface as an exception from this call.
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(value)
            staged = tmp.name
        try:
            self.put_file(staged, path, **kwargs)
        finally:
            os.unlink(staged)

    def _rm_file(self, path: str, **kwargs: Any) -> None:
        url = self._url(path)
        path = self._strip_protocol(path)
        with self._opts(recursive=bool(kwargs.get("recursive"))) as opts:
            _lib.check(lib.pelican_delete(ffi.NULL, url.encode(), opts))

    def rm_file(self, path: str) -> None:
        self._rm_file(path)

    def mkdir(self, path: str, create_parents: bool = True, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Pelican namespaces have no explicit directory creation; write an "
            "object at the desired path instead"
        )

    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        raise NotImplementedError(
            "Pelican namespaces have no explicit directory creation; write an "
            "object at the desired path instead"
        )

    # ---------------------------------------------------------------- #
    # Native file handles                                              #
    # ---------------------------------------------------------------- #

    def _handle(self, path: str, flags: int) -> _Handle:
        return _Handle(self, path, flags)


class _Handle:
    """Context manager around an open pelican_file."""

    def __init__(self, fs: PelicanNativeFileSystem, path: str, flags: int):
        self._fs = fs
        self._path = path
        self._flags = flags
        self.ptr: Any = None

    def __enter__(self) -> _Handle:
        self.open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def open(self) -> None:
        url = self._fs._url(self._path)
        out = ffi.new("pelican_file **")
        with self._fs._opts() as opts:
            _lib.check(lib.pelican_fs_open(url.encode(), self._flags, opts, out))
        if out[0] == ffi.NULL:
            raise PelicanClientError(f"opening {self._path!r} produced no handle")
        self.ptr = out[0]

    def close(self) -> None:
        if self.ptr is None:
            return
        ptr, self.ptr = self.ptr, None
        # pelican_file_close frees the handle even when it reports an
        # error, and for writes it is where the upload is finalized --
        # so its result is the operation's result, not a courtesy.
        _lib.check(lib.pelican_file_close(ptr))


def _err_out() -> Any:
    return ffi.new("pelican_error **")


def _raise_io(err_out: Any, context: str) -> None:
    if err_out[0] != ffi.NULL:
        _lib.check(err_out[0])
    raise PelicanClientError(f"{context} failed without reporting an error")


def _pread(handle: _Handle, offset: int, length: int) -> bytes:
    """Read exactly ``length`` bytes at ``offset``, or fewer at EOF."""
    chunks: list[bytes] = []
    got = 0
    buf = ffi.new("char[]", length) if length else None
    while got < length:
        err = _err_out()
        n = lib.pelican_file_pread(
            handle.ptr, buf, length - got, offset + got, err
        )
        if n < 0:
            _raise_io(err, "pread")
        if n == 0:
            break
        chunks.append(bytes(ffi.buffer(buf, n)))
        got += n
    return b"".join(chunks)


def _read_all(handle: _Handle, offset: int = 0, chunk: int = 1 << 20) -> bytes:
    chunks: list[bytes] = []
    buf = ffi.new("char[]", chunk)
    pos = offset
    while True:
        err = _err_out()
        n = lib.pelican_file_pread(handle.ptr, buf, chunk, pos, err)
        if n < 0:
            _raise_io(err, "read")
        if n == 0:
            break
        chunks.append(bytes(ffi.buffer(buf, n)))
        pos += n
    return b"".join(chunks)


class PelicanNativeFile(AbstractBufferedFile):
    """A file-like view of a remote object, read through positional reads."""

    def __init__(self, fs: PelicanNativeFileSystem, path: str, mode: str = "rb", **kwargs: Any):
        self._handle: _Handle | None = None
        self._write_buffer: list[bytes] = []
        super().__init__(fs, path, mode=mode, **kwargs)
        if "r" in mode:
            self._handle = fs._handle(self.path, _lib.O_RDONLY)
            self._handle.open()

    def _fetch_range(self, start: int, end: int) -> bytes:
        assert self._handle is not None
        return _pread(self._handle, start, max(end - start, 0))

    def _initiate_upload(self) -> None:
        # Writes are staged locally and uploaded on close.  The library's
        # streaming write would work, but an fsspec writer may be flushed
        # many times and the Go side finalizes only at close; staging
        # keeps "the exception comes from close()" true either way.
        self._write_buffer = []

    def _upload_chunk(self, final: bool = False) -> bool:
        self._write_buffer.append(self.buffer.getvalue())
        if final:
            payload = b"".join(self._write_buffer)
            self._write_buffer = []
            self.fs.pipe_file(self.path, payload)
        return True

    def close(self) -> None:
        try:
            super().close()
        finally:
            if self._handle is not None:
                handle, self._handle = self._handle, None
                handle.close()


class OSDFNativeFileSystem(PelicanNativeFileSystem):
    """The OSDF federation, preconfigured."""

    protocol = "osdf+native"

    def __init__(self, **kwargs: Any):
        kwargs.setdefault("federation_discovery_url", _OSDF_DISCOVERY)
        super().__init__(**kwargs)
