"""Generative differential fuzzing of operations against the federation.

Phase two.  Where :mod:`test_fuzz_paths` compares two pure functions at
microsecond cost, every example here is real network I/O against the
federation the session fixture launched, so the budget is deliberately
small: ``NETWORK_BUDGET_DIVISOR`` examples fewer than the pure fuzzer
(see ``conftest``), which keeps a push-time run in the seconds while
``--hypothesis-profile=soak`` still buys a long hunt.

The oracle is the same idea as phase one and the same as the hand-written
tests next door: run the operation on both implementations, reduce a
failure to its exception type with ``_attempt``, and require the results
to be equal.  Known divergences are absorbed by a function that names
the register key responsible, so an unexplained difference -- the only
kind worth a human's time -- is what fails.

Sizes come from the export directory on disk rather than from either
``info()``, so the thing the range arithmetic is checked against is
neither implementation's opinion.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import NETWORK_BUDGET_DIVISOR
from test_differential import _attempt, normalize, reason

pelicanfs_exceptions = pytest.importorskip(
    "pelicanfs.exceptions", reason="install the 'differential' dependency group"
)

pytestmark = pytest.mark.differential

# Each example is a round trip to a director, a cache and an origin.
NETWORK_EXAMPLES = max(5, settings().max_examples // NETWORK_BUDGET_DIVISOR)

# Objects that exist in the export the federation fixture builds.
PRESENT = ["hello_world.txt", "empty.txt", "subdir/nested.txt"]

# A read range can land anywhere around a 13-byte object; +/-20 reaches
# past both ends with room to spare, and keeps shrinking fast.
OFFSETS = st.one_of(st.none(), st.integers(min_value=-20, max_value=20))


def spellings_of(obj: str) -> list[str]:
    """Suffix spellings that all denote the same object."""
    return [obj, f"{obj}/", f"./{obj}", f"/{obj}"]


# Whole-path forms.  The schemeless host-first form -- "host/ns/obj",
# which both libraries document -- is missing on purpose: this
# federation runs on an ephemeral port, and urlparse reads
# "localhost:63371/..." as a URL with the scheme "localhost", so neither
# library can address it. They fail differently, which is
# exists-raises-on-an-unusable-path, pinned below.
FORMS = ["{ns}/{rest}", "pelican://{host}{ns}/{rest}"]


def address(federation, form: str, rest: str) -> str:
    return form.format(
        ns=federation.namespace,
        host=federation.discovery_url.removeprefix("pelican://"),
        rest=rest.lstrip("/"),
    )


def _resolve(bound: int | None, default: int, size: int) -> int:
    """A slice bound, resolved against the size but *not* clamped.

    Clamping is the thing under test, so the oracle must not do it.
    """
    if bound is None:
        return default
    return bound if bound >= 0 else size + bound


def _explains_range(size: int, start: int | None, end: int | None) -> str | None:
    """Name the registered divergence a range difference belongs to.

    fsspec specifies ``cat_file``'s start and end as Python slice
    bounds, so this is just which part of that contract pelicanfs does
    not implement.  The three classes partition every disagreement in a
    169-pair sweep with none left over (docs/FUZZER-NOTES.md).

    Order matters where classes overlap -- a start past the end is also
    an empty range -- and the pre-existing register entry is checked
    first so the two new ones stay as narrow as what they describe.

    Note what is *not* here.  Negative bounds as such:
    ``cat_file(path, -5, -1)`` works on both, and the first reading of
    the sweep said negatives were the problem and was wrong.  Nor is a
    range whose bounds are *equal*: ``cat_file(path, 5, 5)`` returns
    ``b''`` from both, so only a strictly inverted range is absorbed --
    equality is held to agreeing, which it does.
    """
    begin = _resolve(start, 0, size)
    stop = _resolve(end, size, size)
    if begin >= size:
        return "range-entirely-past-eof"
    if begin < 0:
        return "range-start-before-the-beginning"
    if stop < begin:
        return "inverted-or-empty-range"
    return None


def basenames(entries, leaf: str) -> list[str]:
    """A listing reduced to the names of its members.

    ``leaf`` is the listed collection's own name, which the caller
    passes rather than deriving from the spelling -- the spellings
    under test include ``subdir/.``, whose last component is not the
    collection's name.  No member of the test export shares a name with
    its parent, so dropping by name is unambiguous here.

    Two absorptions, each a registered divergence with its own pin:
    ``ls-names-are-endpoint-paths`` (pelicanfs names entries by the
    origin endpoint they were answered from) and
    ``ls-echoes-the-collection-itself`` (its listing includes the
    collection).  What is left is the one thing both sides claim to
    report: which members the collection has.
    """
    names = [e if isinstance(e, str) else e["name"] for e in entries]
    trimmed = [n.rstrip("/").rsplit("/", 1)[-1] for n in names]
    return sorted(n for n in trimmed if n != leaf)


def _report(label: str, native, pure) -> str:
    return f"\n{label}\nnative     {native!r}\npelicanfs  {pure!r}"


# --------------------------------------------------------------------- #
# Reads                                                                 #
# --------------------------------------------------------------------- #


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(OFFSETS, OFFSETS)
def test_cat_file_ranges_agree(native_fs, pelicanfs_fs, federation, start, end):
    """A ranged read must return the same bytes from both clients."""
    obj = "hello_world.txt"
    path = federation.path(obj)
    size = (federation.export_dir / obj).stat().st_size
    native = _attempt(native_fs.cat_file, path, start, end)
    pure = _attempt(pelicanfs_fs.cat_file, path, start, end)
    if native == pure:
        return
    key = _explains_range(size, start, end)
    assert key is not None, (
        f"unexplained divergence on cat_file(start={start!r}, end={end!r}) "
        f"over {size} bytes" + _report(path, native, pure)
    )
    assert isinstance(pure, tuple), (
        f"{key} says pelicanfs raises for (start={start!r}, end={end!r}), "
        "but it returned a value" + _report(path, native, pure)
    )


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(st.sampled_from(PRESENT))
def test_cat_file_agrees(native_fs, pelicanfs_fs, federation, obj):
    """A whole-object read, over every object in the export."""
    path = federation.path(obj)
    expected = (federation.export_dir / obj).read_bytes()
    native = _attempt(native_fs.cat_file, path)
    pure = _attempt(pelicanfs_fs.cat_file, path)
    assert native == pure == expected, _report(path, native, pure)


# --------------------------------------------------------------------- #
# Metadata                                                              #
# --------------------------------------------------------------------- #


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(
    st.sampled_from(PRESENT + ["no-such-object", "subdir/no-such-object"]),
    st.integers(min_value=0, max_value=3),
    st.sampled_from(FORMS),
)
def test_exists_agrees(native_fs, pelicanfs_fs, federation, obj, spelling_index, form):
    """Spellings of one object must all get the same answer, on both sides."""
    path = address(federation, form, spellings_of(obj)[spelling_index])
    native = _attempt(native_fs.exists, path)
    pure = _attempt(pelicanfs_fs.exists, path)
    assert native == pure, _report(path, native, pure)


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(st.sampled_from(PRESENT), st.integers(min_value=0, max_value=3))
def test_info_agrees_on_size(native_fs, new_pelicanfs, federation, obj, spelling_index):
    """``info()`` must report the size the file has on disk.

    A fresh pelicanfs per example, because its ``info`` leaves state
    behind that misdirects the next call (``info-is-stateful``); a
    shared instance would make this fail for that unrelated reason, and
    an instance built without ``skip_instance_cache=True`` would not be
    fresh at all -- fsspec keys its cache on the storage options.
    """
    path = federation.path(spellings_of(obj)[spelling_index])
    expected = (federation.export_dir / obj).stat().st_size
    native = normalize(native_fs.info(path))
    pure = normalize(new_pelicanfs().info(path))
    assert native["size"] == pure["size"] == expected, _report(path, native, pure)


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(
    st.sampled_from(["subdir", "subdir/", "./subdir", "subdir/."]),
    st.sampled_from(FORMS),
)
def test_ls_agrees(native_fs, pelicanfs_fs, federation, collection, form):
    """Every spelling of a collection must list the same members.

    ``detail=False`` only: ``detail=True`` raises on pelicanfs for any
    collection at all (``ls-crashes-on-a-subcollection``), which
    ``test_differential`` already pins.  Generating that case here
    would spend network round trips re-finding a known bug.
    """
    path = address(federation, form, collection)
    native = _attempt(native_fs.ls, path, False)
    pure = _attempt(pelicanfs_fs.ls, path, False)
    if isinstance(native, list) and isinstance(pure, list):
        native, pure = basenames(native, "subdir"), basenames(pure, "subdir")
    assert native == pure, _report(path, native, pure)


# --------------------------------------------------------------------- #
# Pins                                                                  #
# --------------------------------------------------------------------- #


@pytest.mark.xfail(strict=True, reason=reason("range-start-before-the-beginning"))
def test_range_start_before_the_beginning_agrees(
    native_fs, pelicanfs_fs, federation
):
    """A slice bound further back than the object is long clamps.

    ``data[-20:-5]`` on 13 bytes is ``data[0:8]``, and the native client
    clamps the same way; pelicanfs forwards the unclamped offset into a
    Range header and the origin answers 416.  The in-range negative
    case ``(-5, -1)`` is asserted first, as the control that says this
    is about clamping and not about negatives.
    """
    path = federation.path("hello_world.txt")
    data = b"Hello, World!"
    assert _attempt(pelicanfs_fs.cat_file, path, -5, -1) == data[-5:-1]
    assert _attempt(native_fs.cat_file, path, -20, -5) == data[-20:-5]
    assert _attempt(pelicanfs_fs.cat_file, path, -20, -5) == data[-20:-5]


@pytest.mark.xfail(strict=True, reason=reason("inverted-or-empty-range"))
def test_empty_range_agrees(native_fs, pelicanfs_fs, federation):
    """A range that selects nothing should read nothing, not fail."""
    path = federation.path("hello_world.txt")
    for start, end in ((0, 0), (5, 5), (5, 1)):
        assert _attempt(native_fs.cat_file, path, start, end) == b"", (start, end)
        assert _attempt(pelicanfs_fs.cat_file, path, start, end) == b"", (start, end)


@pytest.mark.xfail(strict=True, reason=reason("ls-names-are-endpoint-paths"))
def test_ls_names_are_addressable(pelicanfs_fs, federation):
    """A name ls() returns must be one its own info() accepts."""
    path = federation.path("subdir")
    for name in pelicanfs_fs.ls(path, detail=False):
        assert name.startswith(federation.namespace), name


@pytest.mark.xfail(strict=True, reason=reason("ls-echoes-the-collection-itself"))
def test_ls_does_not_echo_the_collection(pelicanfs_fs, federation):
    """A listing is a collection's members, not the collection.

    The native side drops the self-entry explicitly, because ``find``
    and ``walk`` recurse forever otherwise.
    """
    path = federation.path("subdir")
    names = [n.rstrip("/") for n in pelicanfs_fs.ls(path, detail=False)]
    assert not any(n.endswith("/subdir") for n in names), names


@pytest.mark.xfail(strict=True, reason=reason("exists-raises-on-an-unusable-path"))
def test_exists_does_not_raise(native_fs, pelicanfs_fs):
    """``exists()`` answers a question; it should not raise.

    fsspec's own ``AbstractFileSystem.exists`` catches everything and
    returns False, which is what the native side inherits.  pelicanfs
    overrides ``_exists`` and lets ``_check_fspath``'s rejection escape,
    so a caller sweeping a list of candidate paths gets an exception
    from one spelling and a bool from the next.
    """
    for path in ("s3://bucket/key", "localhost:1/ns/obj"):
        assert native_fs.exists(path) is False, path
        assert pelicanfs_fs.exists(path) is False, path


@pytest.mark.xfail(strict=True, reason=reason("strip-protocol-rejects-a-port"))
def test_glob_accepts_a_url_that_info_accepts(native_fs, new_pelicanfs, federation):
    """One object must not be addressable by ``info`` but not by ``glob``.

    ``glob`` strips the protocol first, leaving ``localhost:NNNN/...``,
    in which urlparse reads ``localhost`` as a scheme; every other
    method takes the same URL, because they hand the unstripped string
    to ``_check_fspath``.  The test federation runs on an ephemeral
    port, so it reproduces this for free.

    Only ``InvalidDestinationURL`` counts as a failure here.  pelicanfs
    also cannot list this collection (``ls-crashes-on-a-subcollection``)
    and ``glob`` goes on to hit that; letting the other bug fail this
    test would leave the xfail stuck after this one is fixed.
    """
    url = f"{federation.discovery_url}{federation.namespace}/subdir/nested.txt"
    assert native_fs.glob(url) == [federation.path("subdir/nested.txt")]
    new_pelicanfs().info(url)  # the control: this URL is addressable
    try:
        new_pelicanfs().glob(url)
    except pelicanfs_exceptions.InvalidDestinationURL as exc:
        pytest.fail(f"glob refused a URL that info accepted: {exc}")
    except Exception:  # noqa: BLE001 -- another divergence's business
        pass
