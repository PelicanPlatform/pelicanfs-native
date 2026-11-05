"""The differential oracle: pelicanfs_native vs pelicanfs.

Two independent implementations of one contract, driven against one
federation.  A disagreement is a finding in one of them -- the harness's
job is to make sure a disagreement is never merely cosmetic.

Normalization lives here rather than in either library.  Each library
should implement the fsspec contract as directly as it can; bending one
to match the other's quirks is how a differential oracle stops finding
anything.  What survives :func:`normalize` is a real difference.

Known divergences are declared in ``KNOWN_DIVERGENCES`` and marked
xfail(strict=True), so the suite stays green while a divergence lasts
and fails loudly the day it is fixed and the entry goes stale.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest

pytestmark = pytest.mark.differential


# Each entry: why the two differ today, and which side we believe.
KNOWN_DIVERGENCES = {
    "info-type": (
        "pelicanfs._info hardcodes type='file' and never reports a "
        "collection, while the native client has IsCollection. The native "
        "side is right; pelicanfs needs a fix."
    ),
    "info-mtime-shape": (
        "pelicanfs reports mtime as an unparsed string from _info and as a "
        "datetime under the key 'modified' from _ls; the native side reports "
        "an int epoch. fsspec does not pin this, but one class should not "
        "use two shapes."
    ),
    "info-name-is-the-endpoint-path": (
        "pelicanfs._info returns the name it was ANSWERED from -- "
        "'/api/v1.0/origin/data/ns/obj' -- rather than the namespace path "
        "'/ns/obj' the caller asked for. That name cannot be handed back to "
        "open() or ls(), which the fsspec contract requires. The underlying "
        "library echoes the same endpoint path from stat, so pelicanfs is "
        "passing a wart through where pelicanfs_native normalizes it; "
        "pelicanfs needs the fix."
    ),
    "ls-crashes-on-a-subcollection": (
        "pelicanfs._ls_real does int(item['size']) on every entry, and a "
        "collection's PROPFIND size property is empty, so listing any "
        "collection that contains a subdirectory raises "
        "ValueError: invalid literal for int() with base 10: ''. "
        "A clear pelicanfs bug; the native side lists it fine."
    ),
    "info-is-stateful": (
        "The first pelicanfs info() on a filesystem instance succeeds and "
        "every later one on that instance raises FileNotFoundError. Each "
        "object stats fine as the first call on a genuinely fresh instance "
        "and fails as the second, so the state is per-instance: the first "
        "call caches a resolved endpoint URL that is then reused for "
        "unrelated paths -- the same endpoint path info() hands back as the "
        "object's name. This bites every real caller, because fsspec keys "
        "its instance cache on the storage options and hands the same "
        "PelicanFileSystem to everyone with the same federation. The most "
        "serious finding here, and a pelicanfs bug."
    ),
    "range-entirely-past-eof": (
        "A read whose whole range lies past the end of the object: the "
        "native client returns b'', pelicanfs raises. fsspec does not pin "
        "this -- HTTP would answer 416 while a local filesystem returns b'' "
        "-- so this one needs a decision before either side is called wrong."
    ),
}


def _coerce_mtime(value: Any) -> int | None:
    """Reduce any of the three mtime shapes to an epoch second."""
    if value in (None, "", "None"):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime.datetime):
        return int(value.timestamp())
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return int(datetime.datetime.strptime(value, fmt).timestamp())
        except (ValueError, TypeError):
            continue
    return None


def normalize(entry: dict[str, Any]) -> dict[str, Any]:
    """Reduce an fsspec entry to the fields both sides claim to provide.

    Only shape differences are absorbed -- key spelling and mtime
    encoding. Values are never adjusted.
    """
    name = str(entry.get("name", ""))
    # fsspec does not pin whether a collection's name carries a trailing
    # slash; the object identity is the same either way.
    normalized_name = name.rstrip("/") or "/"
    mtime = entry.get("mtime", entry.get("modified"))
    return {
        "name": normalized_name,
        "size": entry.get("size"),
        "type": entry.get("type"),
        "mtime": _coerce_mtime(mtime),
    }


def normalize_listing(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((normalize(e) for e in entries), key=lambda e: e["name"])


def compare(native: dict[str, Any], pure: dict[str, Any], *, fields: tuple[str, ...]) -> None:
    for field in fields:
        assert native[field] == pure[field], (
            f"{field}: native={native[field]!r} pelicanfs={pure[field]!r}"
        )


# --------------------------------------------------------------------- #
# Reads                                                                 #
# --------------------------------------------------------------------- #

OBJECTS = ["hello_world.txt", "empty.txt", "binary.bin", "subdir/nested.txt"]


@pytest.mark.parametrize("obj", OBJECTS)
def test_cat_file_agrees(native_fs, pelicanfs_fs, federation, obj):
    path = federation.path(obj)
    assert native_fs.cat_file(path) == pelicanfs_fs.cat_file(path)


RANGES = [
    (0, 5),
    (7, 12),
    (0, 0),
    (3, None),
    (None, 4),
    (0, 10_000),
    pytest.param(
        10_000, 10_010,
        marks=pytest.mark.xfail(
            strict=True, reason=KNOWN_DIVERGENCES["range-entirely-past-eof"]
        ),
    ),
]


@pytest.mark.parametrize(("start", "end"), RANGES)
def test_cat_file_ranges_agree(native_fs, pelicanfs_fs, federation, start, end):
    path = federation.path("hello_world.txt")
    native = _attempt(native_fs.cat_file, path, start, end)
    pure = _attempt(pelicanfs_fs.cat_file, path, start, end)
    assert native == pure, f"range ({start}, {end}): native={native!r} pelicanfs={pure!r}"


def _attempt(fn, *args, **kwargs):
    """Run an operation, representing a failure by its exception type.

    Comparing exception *types* keeps the oracle honest about error
    behavior without tying it to either library's message wording.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 -- the type is the result
        for base in (FileNotFoundError, PermissionError, FileExistsError, ValueError):
            if isinstance(exc, base):
                return ("raised", base.__name__)
        return ("raised", "Exception")


# --------------------------------------------------------------------- #
# Metadata                                                              #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("obj", OBJECTS)
def test_info_agrees_on_size(native_fs, new_pelicanfs, federation, obj):
    # A fresh pelicanfs per object: this test is about size agreement,
    # and sharing an instance would make it fail for an unrelated reason
    # (test_pelicanfs_info_is_stateful).
    path = federation.path(obj)
    native = normalize(native_fs.info(path))
    pure = normalize(new_pelicanfs().info(path))
    compare(native, pure, fields=("size",))


@pytest.mark.xfail(strict=True, reason=KNOWN_DIVERGENCES["info-is-stateful"])
def test_pelicanfs_info_is_stateful(new_pelicanfs, federation):
    """A second info() on one instance must not fail because of the first.

    Each object stats fine as the first call on a fresh filesystem and
    raises FileNotFoundError as the second, so the first call leaves
    behind state that misdirects the next one -- consistent with the
    resolved endpoint path that info() also returns as the object's
    name.
    """
    fs = new_pelicanfs()
    fs.info(federation.path("hello_world.txt"))
    fs.info(federation.path("empty.txt"))


def test_native_info_is_not_stateful(native_fs, federation):
    """The same sequence against the native client, as a control."""
    for obj in OBJECTS:
        assert native_fs.info(federation.path(obj))["type"] == "file"


@pytest.mark.xfail(strict=True, reason=KNOWN_DIVERGENCES["info-name-is-the-endpoint-path"])
def test_info_agrees_on_name(native_fs, pelicanfs_fs, federation):
    path = federation.path("hello_world.txt")
    native = normalize(native_fs.info(path))
    pure = normalize(pelicanfs_fs.info(path))
    compare(native, pure, fields=("name",))


def test_info_name_is_addressable(native_fs, federation):
    """Whatever info() names must be openable -- the contract pelicanfs breaks."""
    path = federation.path("hello_world.txt")
    assert native_fs.cat_file(native_fs.info(path)["name"]) == b"Hello, World!"


@pytest.mark.xfail(strict=True, reason=KNOWN_DIVERGENCES["info-type"])
def test_info_agrees_on_type_for_a_collection(native_fs, pelicanfs_fs, federation):
    path = federation.path("subdir")
    native = normalize(native_fs.info(path))
    pure = normalize(pelicanfs_fs.info(path))
    compare(native, pure, fields=("type",))


@pytest.mark.xfail(strict=True, reason=KNOWN_DIVERGENCES["ls-crashes-on-a-subcollection"])
def test_ls_agrees(native_fs, pelicanfs_fs, federation):
    native = normalize_listing(native_fs.ls(federation.namespace, detail=True))
    pure = normalize_listing(pelicanfs_fs.ls(federation.namespace, detail=True))
    assert [e["name"] for e in native] == [e["name"] for e in pure]
    for n, p in zip(native, pure, strict=True):
        compare(n, p, fields=("size", "type"))


def test_exists_agrees(native_fs, pelicanfs_fs, federation):
    for obj in [*OBJECTS, "no-such-object", "subdir", "subdir/no-such-object"]:
        path = federation.path(obj)
        assert native_fs.exists(path) == pelicanfs_fs.exists(path), path


@pytest.mark.xfail(strict=True, reason=KNOWN_DIVERGENCES["ls-crashes-on-a-subcollection"])
def test_find_agrees(native_fs, pelicanfs_fs, federation):
    native = sorted(p.rstrip("/") for p in native_fs.find(federation.namespace))
    pure = sorted(p.rstrip("/") for p in pelicanfs_fs.find(federation.namespace))
    assert native == pure


# --------------------------------------------------------------------- #
# The path corpus -- the seed for a future generative fuzzer            #
# --------------------------------------------------------------------- #
#
# Every entry here is a spelling of a path, valid or not.  The oracle
# asserts only that both implementations reach the same verdict, so a
# new spelling can be added without deciding up front what it means.
# A generator that mutates these is the natural next step.

PATH_SPELLINGS = [
    "{ns}/hello_world.txt",
    "{ns}/hello_world.txt/",
    "{ns}//hello_world.txt",
    "{ns}/./hello_world.txt",
    "{ns}/subdir/../hello_world.txt",
    "{ns}/subdir",
    "{ns}/subdir/",
    "{ns}",
    "{ns}/",
    "{ns}/no-such-object",
    "{ns}/sub dir with spaces/x",
    "{ns}/percent%20encoded.txt",
    "{ns}/unicode-éè.txt",
    "{ns}/trailing.space ",
    "{ns}/.hidden",
    "{ns}/a?query=1",
    "{ns}/a#fragment",
    "pelican://{host}{ns}/hello_world.txt",
]


@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_path_spellings_agree(native_fs, pelicanfs_fs, federation, spelling):
    """Both implementations must agree on what a path spelling denotes.

    This is the axis that has produced real pelicanfs bugs -- namespace
    prefix matching on path boundaries, trailing-slash handling, and
    globbing over pelican:// and osdf:// URLs were all fixed recently.
    """
    host = federation.discovery_url.removeprefix("pelican://")
    path = spelling.format(ns=federation.namespace, host=host)
    native = _attempt(native_fs.exists, path)
    pure = _attempt(pelicanfs_fs.exists, path)
    assert native == pure, f"{path!r}: native={native!r} pelicanfs={pure!r}"
