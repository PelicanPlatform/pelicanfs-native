"""The differential oracle: pelicanfs_native vs pelicanfs.

Two independent implementations of one contract, driven against one
federation.  A disagreement is a finding in one of them -- the harness's
job is to make sure a disagreement is never merely cosmetic.

Normalization lives here rather than in either library.  Each library
should implement the fsspec contract as directly as it can; bending one
to match the other's quirks is how a differential oracle stops finding
anything.  What survives :func:`normalize` is a real difference.

Known divergences live in ``KNOWN_DIVERGENCES.toml`` at the repository
root, and each is pinned here by an xfail(strict=True) whose reason is
that entry's summary.  The suite therefore stays green while a
divergence lasts and fails the day it is fixed, which is the signal to
delete the entry.
"""

from __future__ import annotations

import datetime
import tomllib
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.differential

REGISTER = Path(__file__).resolve().parent.parent / "KNOWN_DIVERGENCES.toml"
KNOWN_DIVERGENCES = tomllib.loads(REGISTER.read_text())

# Which entries this module actually pins. Populated at import time,
# because xfail markers are applied during collection, so by the time
# any test runs every reason() call has already happened.
_pinned: set[str] = set()


def reason(key: str) -> str:
    """The xfail reason for a registered divergence.

    Going through here rather than indexing the dict directly is what
    lets test_register_has_no_stale_entries notice an entry that no
    test pins any more.
    """
    entry = KNOWN_DIVERGENCES[key]
    _pinned.add(key)
    return f"[{key}, blame={entry['blame']}] {entry['summary'].strip()}"


def test_register_is_well_formed():
    """Every entry carries the fields the register documents."""
    assert KNOWN_DIVERGENCES, f"no divergences loaded from {REGISTER}"
    for key, entry in KNOWN_DIVERGENCES.items():
        missing = {"summary", "blame", "found"} - set(entry)
        assert not missing, f"{key} is missing {sorted(missing)}"
        assert entry["blame"] in {
            "pelicanfs",
            "pelicanfs-native",
            "upstream",
            "undecided",
        }, f"{key} has an unknown blame {entry['blame']!r}"


def test_register_has_no_stale_entries():
    """An entry no test pins is a divergence nobody is watching.

    This fires when a divergence is fixed and its xfail is deleted but
    the entry is left behind, which would otherwise quietly become
    folklore.
    """
    stale = set(KNOWN_DIVERGENCES) - _pinned
    assert not stale, (
        f"{sorted(stale)} are in {REGISTER.name} but no test pins them; "
        f"delete the entries or add the tests"
    )


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
            strict=True, reason=reason("range-entirely-past-eof")
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


@pytest.mark.xfail(strict=True, reason=reason("info-is-stateful"))
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


@pytest.mark.xfail(strict=True, reason=reason("info-name-is-the-endpoint-path"))
def test_info_agrees_on_name(native_fs, pelicanfs_fs, federation):
    path = federation.path("hello_world.txt")
    native = normalize(native_fs.info(path))
    pure = normalize(pelicanfs_fs.info(path))
    compare(native, pure, fields=("name",))


def test_info_name_is_addressable(native_fs, federation):
    """Whatever info() names must be openable -- the contract pelicanfs breaks."""
    path = federation.path("hello_world.txt")
    assert native_fs.cat_file(native_fs.info(path)["name"]) == b"Hello, World!"


@pytest.mark.xfail(strict=True, reason=reason("info-mtime-shape"))
def test_info_mtime_shapes_agree(native_fs, new_pelicanfs, federation):
    """The two should describe a timestamp the same way.

    normalize() absorbs this difference on purpose, so no other test in
    this module can see it; without this one the register entry would
    be prose with nothing behind it.
    """
    path = federation.path("hello_world.txt")
    native = native_fs.info(path)["mtime"]
    pure = new_pelicanfs().info(path)["mtime"]
    assert type(native) is type(pure), (
        f"mtime shapes differ: native={native!r} ({type(native).__name__}) "
        f"pelicanfs={pure!r} ({type(pure).__name__})"
    )


@pytest.mark.xfail(strict=True, reason=reason("info-type"))
def test_info_agrees_on_type_for_a_collection(native_fs, pelicanfs_fs, federation):
    path = federation.path("subdir")
    native = normalize(native_fs.info(path))
    pure = normalize(pelicanfs_fs.info(path))
    compare(native, pure, fields=("type",))


@pytest.mark.xfail(strict=True, reason=reason("ls-crashes-on-a-subcollection"))
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


@pytest.mark.xfail(strict=True, reason=reason("ls-crashes-on-a-subcollection"))
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
