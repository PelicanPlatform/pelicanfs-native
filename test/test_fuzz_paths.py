"""Generative differential fuzzing of path handling.

Phase one of the fuzzer, and the cheapest high-value surface there is:
the functions that turn a path *spelling* into the object it denotes are
pure, so an example costs microseconds and hundreds of thousands of them
fit in a CI budget.  It is also where ``pelicanfs``'s real bug history
lives -- namespace prefix matching on path boundaries, trailing slashes
surviving or not, and globbing over ``pelican://`` and ``osdf://`` URLs
were all recent fixes.

The oracle predicate
====================

The two implementations do not have matching signatures, so "agree" has
to be defined rather than assumed.  What a caller actually depends on is
*denotation*: for a filesystem bound to federation ``F``, which object
does the spelling ``S`` name, or is ``S`` refused?  So each side is
reduced to one of

    ("ok", <canonical namespace path>)      -- S denotes that object
    ("reject",)                             -- S names nothing here

and the oracle asserts the two reductions are equal.  Three things are
deliberately *not* part of the predicate, each for a stated reason:

* **The exception type on a rejection.**  The two libraries raise from
  unrelated hierarchies (``ValueError`` versus
  ``pelicanfs.exceptions.PelicanException``, a ``RuntimeError``).  That
  is itself a divergence, so it is absorbed here and pinned by
  :func:`test_path_rejections_share_an_exception_type` rather than
  drowning every other signal.

* **Trailing separators.**  ``_strip_protocol`` is specified by fsspec to
  drop them and does; ``_check_fspath`` is an internal function with no
  such contract and keeps them.  ``canonical`` drops them on both sides,
  which is the same thing the existing ``normalize`` in
  ``test_differential`` does for entry names.

* **The ``+native`` scheme aliases.**  The two distributions must not
  claim the same fsspec protocol name (see the README), so a caller who
  writes ``pelican+native://`` means exactly what ``pelican://`` means.
  :func:`for_pelicanfs` rewrites the alias away before pelicanfs sees
  it; this is a difference in registration, not in path semantics.

Which side's entry points
-------------------------

Each side is driven through the functions its own filesystem really
calls, not through whichever pair happens to line up:

* native: ``_url()`` (which is ``_split_url`` plus the foreign-federation
  check) followed by ``_strip_protocol()``, which is literally what
  ``info``, ``ls`` and ``cat_file`` do in ``core.py``.
* pelicanfs: ``_check_fspath()``, which is what its ``_dirlist_dec`` and
  ``_match_namespace`` decorators call for ``info``, ``exists`` and
  ``cat_file``.

pelicanfs has a *second*, inconsistent front door -- ``_strip_protocol``,
which ``_glob`` uses -- and the two do not compose.  That is a finding in
its own right; see the register and
:func:`test_native_path_front_doors_compose` for the control.

Known divergences are absorbed by :func:`_explained_by`, which names the
register key for each one at the point of absorption.  An *unexplained*
difference fails, prints the spelling and both outcomes, and Hypothesis
shrinks it to the smallest spelling that still shows it.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pelicanfs_native.core import PelicanNativeFileSystem

from path_strategies import HOSTS, spellings
from test_differential import reason

pytestmark = pytest.mark.differential

pelicanfs_core = pytest.importorskip(
    "pelicanfs.core", reason="install the 'differential' dependency group"
)
PelicanFileSystem = pelicanfs_core.PelicanFileSystem

# These are pure functions; the default profile's budget is spent here.
# See conftest for the profiles and README for the soak profile.
PURE_EXAMPLES = settings().max_examples

NATIVE_ALIASES = ("pelican+native", "osdf+native")


# --------------------------------------------------------------------- #
# Reducing each implementation to a denotation                          #
# --------------------------------------------------------------------- #


def for_pelicanfs(spelling: str) -> str:
    """Rewrite a ``+native`` scheme alias to the name pelicanfs knows.

    The alias exists only so the two distributions can both register
    with fsspec (README, "Relationship to pelicanfs"). Handing pelicanfs
    a scheme it never claimed would make every alias case a trivial,
    uninteresting rejection and hide the path semantics underneath.
    """
    lowered = spelling.lower()
    for alias in NATIVE_ALIASES:
        if lowered.startswith(alias + ":"):
            return spelling.replace("+native", "", 1)
    return spelling


def canonical(namespace_path: str) -> str:
    """Drop trailing separators, which neither side promises to keep."""
    return namespace_path.rstrip("/") or "/"


def native_denotation(spelling: str, federation: str) -> tuple:
    """What ``PelicanNativeFileSystem`` makes of a spelling.

    A stub instance rather than a constructed one: the constructor
    initializes the Go runtime, which is a once-per-process, global
    thing, and nothing below ``_url`` touches anything but
    ``discovery_url``. ``test_paths`` already uses this shape (see
    ``test_url_rejects_a_foreign_federation``).
    """
    fs = PelicanNativeFileSystem.__new__(PelicanNativeFileSystem)
    fs.discovery_url = federation
    try:
        fs._url(spelling)
        return ("ok", canonical(fs._strip_protocol(spelling)))
    except Exception as exc:  # noqa: BLE001 -- the verdict is what matters
        return ("reject", type(exc).__name__)


def pelicanfs_denotation(
    spelling: str, federation: str, *, via_strip_protocol: bool = False
) -> tuple:
    """What ``pelicanfs`` makes of a spelling.

    A stub for the same reason the native side uses one, plus a measured
    one: a real ``PelicanFileSystem`` costs 0.27 ms to build and opens an
    aiohttp session, against 0.2 us for the stub -- 1300x, which is the
    difference between a 2000-example budget and a 200 000-example one.
    ``_check_fspath`` reads and writes exactly one attribute.
    ``test_the_pelicanfs_stub_matches_a_real_instance`` guards the
    shortcut.

    pelicanfs canonicalizes ``discovery_url`` with a trailing slash in
    ``__init__``; the stub has to do the same or every URL-spelled
    federation fails ``_validate_discovery_url``'s string comparison --
    which, the first time round, made the whole oracle look green.

    With ``via_strip_protocol``, the spelling goes through pelicanfs's
    *other* front door first, the one ``_glob`` uses.
    """
    fs = PelicanFileSystem.__new__(PelicanFileSystem)
    fs.discovery_url = federation.rstrip("/") + "/"
    given_path = for_pelicanfs(spelling)
    try:
        if via_strip_protocol:
            given_path = fs._strip_protocol(given_path)
        return ("ok", canonical(fs._check_fspath(given_path)))
    except Exception as exc:  # noqa: BLE001 -- the verdict is what matters
        return ("reject", type(exc).__name__)


def _explained_by(spelling: str, native: tuple, pure: tuple) -> str | None:
    """Name the registered divergence that accounts for a difference.

    Returning a key rather than silently normalizing keeps every
    absorption attached to an entry in ``KNOWN_DIVERGENCES.toml`` and to
    the test that pins it, so the fuzzer cannot quietly grow a blind
    spot.
    """
    if native[0] == "reject" and pure[0] == "reject":
        return "path-rejection-exception-class"
    if native[0] == "ok" and pure[0] == "ok":
        parsed = for_pelicanfs(spelling)
        lowered = parsed.lower()
        is_osdf_authority = lowered.startswith("osdf://") and not lowered.startswith(
            "osdf:///"
        )
        if is_osdf_authority and pure[1] == canonical(str(PurePosixPath(native[1]))):
            return "osdf-two-slash-form-is-normalized"
    return None


def _report(spelling: str, federation: str, native: tuple, pure: tuple) -> str:
    return (
        f"\nspelling   {spelling!r}"
        f"\nfederation {federation!r}"
        f"\nnative     {native!r}"
        f"\npelicanfs  {pure!r}"
    )


# --------------------------------------------------------------------- #
# The fuzzer                                                            #
# --------------------------------------------------------------------- #


@settings(max_examples=PURE_EXAMPLES, deadline=None)
@given(spellings(), st.sampled_from(HOSTS))
def test_denotation_agrees(spelling, host):
    """The main property: both sides name the same object, or neither.

    Over 150 000 examples this currently has exactly one unexplained
    class of failure, which is why
    ``osdf-two-slash-form-is-normalized`` exists; anything else the
    generator turns up is new.
    """
    federation = f"pelican://{host}"
    native = native_denotation(spelling, federation)
    pure = pelicanfs_denotation(spelling, federation)
    if native == pure:
        return
    key = _explained_by(spelling, native, pure)
    assert key is not None, (
        "unexplained divergence in what a path spelling denotes."
        + _report(spelling, federation, native, pure)
        + "\nIf this is a real new difference, add it to "
        "KNOWN_DIVERGENCES.toml with a pinning test."
    )


def _strip(spelling: str) -> str | None:
    """``_strip_protocol``, or None where it refuses the spelling.

    Refusing is a documented outcome -- a ``pelican://`` URL with no
    host names no federation (``test_split_url_requires_a_host``) -- so
    the properties below are about what comes back when something does,
    not about totality.
    """
    try:
        return PelicanNativeFileSystem._strip_protocol(spelling)
    except ValueError:
        return None


@settings(max_examples=PURE_EXAMPLES, deadline=None)
@given(spellings())
def test_native_strip_protocol_is_idempotent(spelling):
    """fsspec relies on this: it strips paths it has already stripped."""
    once = _strip(spelling)
    if once is None:
        return
    assert _strip(once) == once, f"{spelling!r} -> {once!r} -> {_strip(once)!r}"


@settings(max_examples=PURE_EXAMPLES, deadline=None)
@given(spellings())
def test_native_strip_protocol_returns_a_rooted_path(spelling):
    """Whatever comes back must be usable as a namespace path.

    A result that is relative, or empty, would be concatenated onto a
    federation URL and silently address something else.
    """
    stripped = _strip(spelling)
    if stripped is None:
        return
    assert stripped.startswith("/"), f"{spelling!r} -> {stripped!r}"


@settings(max_examples=PURE_EXAMPLES, deadline=None)
@given(spellings(), st.sampled_from(HOSTS))
def test_native_path_front_doors_compose(spelling, host):
    """``_strip_protocol``'s output must denote what its input denoted.

    fsspec calls ``_strip_protocol`` wherever it likes -- ``glob`` and
    ``open`` do, ``info`` does not -- so an implementation whose two
    front doors disagree gives different answers depending on which
    method the caller used.  This is the control for the pelicanfs bug
    pinned by ``strip-protocol-loses-the-osdf-federation``.
    """
    federation = f"pelican://{host}"
    direct = native_denotation(spelling, federation)
    if direct[0] != "ok":
        # A spelling naming another federation is refused either way;
        # the information needed to refuse it is gone after stripping,
        # which is why ``info`` resolves the URL before it strips.
        return
    stripped = PelicanNativeFileSystem._strip_protocol(spelling)
    assert native_denotation(stripped, federation) == direct, _report(
        spelling, federation, direct, native_denotation(stripped, federation)
    )


# --------------------------------------------------------------------- #
# Guarding the shortcut the fuzzer takes                                #
# --------------------------------------------------------------------- #

_STUB_CORPUS = [
    "/ns/obj",
    "/ns/obj/",
    "pelican://example.org/ns/obj",
    "pelican://example.org:8443/ns/obj",
    "osdf://ns/obj",
    "osdf:///ns/obj",
    "example.org/ns/obj",
    "s3://bucket/key",
    "pelican://other.example/ns/obj",
    "",
    "/",
]


def test_the_pelicanfs_stub_matches_a_real_instance():
    """The fuzzer's stub must behave like a constructed filesystem.

    Without this, a change to ``PelicanFileSystem.__init__`` -- another
    attribute ``_check_fspath`` comes to depend on, say -- would turn the
    whole phase into a test of the stub.
    """
    for spelling in _STUB_CORPUS:
        real = PelicanFileSystem(
            federation_discovery_url="pelican://example.org",
            # fsspec keys its instance cache on the storage options, so
            # without this every iteration gets the same already-mutated
            # object and the comparison means nothing.
            skip_instance_cache=True,
        )
        try:
            expected = ("ok", canonical(real._check_fspath(spelling)))
        except Exception as exc:  # noqa: BLE001
            expected = ("reject", type(exc).__name__)
        got = pelicanfs_denotation(spelling, "pelican://example.org")
        assert got == expected, f"{spelling!r}: stub={got!r} real={expected!r}"


def test_the_fuzzer_reaches_every_shape():
    """The generator must actually produce each form it claims to.

    A strategy that quietly stopped emitting, say, ``osdf://`` URLs would
    leave the oracle green and blind -- which has already happened once
    in this project, when every ``osdf://`` example was rejected as a
    foreign federation because the federation strategy never offered
    ``osg-htc.org``.
    """
    seen: set[str] = set()

    @settings(max_examples=600, deadline=None, database=None)
    @given(spellings())
    def collect(spelling):
        lowered = spelling.lower()
        if lowered.startswith("pelican+native://") or lowered.startswith("osdf+native://"):
            seen.add("+native alias")
        if lowered.startswith("osdf://") and not lowered.startswith("osdf:///"):
            seen.add("osdf authority")
        if lowered.startswith("osdf:///"):
            seen.add("osdf hostless")
        if lowered.startswith("pelican://") and ":8443" in spelling:
            seen.add("host with port")
        if not lowered.startswith(("pelican", "osdf")) and spelling.startswith("/"):
            seen.add("bare namespace path")
        if not lowered.startswith(("pelican", "osdf", "/")):
            seen.add("schemeless host-first")
        if "%" in spelling:
            seen.add("percent-encoding")
        if "é" in spelling or "é" in spelling:
            seen.add("unicode")
        if "//" in spelling.replace("://", "/:/"):
            seen.add("repeated separator")
        if "/./" in spelling or spelling.endswith("/.") or "/../" in spelling:
            seen.add("dot segment")

    collect()
    expected = {
        "+native alias",
        "osdf authority",
        "osdf hostless",
        "host with port",
        "bare namespace path",
        "schemeless host-first",
        "percent-encoding",
        "unicode",
        "repeated separator",
        "dot segment",
    }
    assert expected <= seen, f"the generator never produced {sorted(expected - seen)}"


# --------------------------------------------------------------------- #
# Pins for the divergences the oracle absorbs                           #
# --------------------------------------------------------------------- #
#
# Deterministic rather than generated on purpose: a pin is a bug report,
# and a strict xfail that depends on the generator finding the case is a
# flake waiting to happen.


@pytest.mark.xfail(strict=True, reason=reason("osdf-two-slash-form-is-normalized"))
def test_osdf_two_slash_form_is_not_normalized():
    """``osdf://ns/./obj`` must denote what ``pelican://f/ns/./obj`` does."""
    federation = "pelican://osg-htc.org"
    for spelling in ("osdf://ns/./obj", "osdf://ns//obj", "osdf://ns/a/./b"):
        assert pelicanfs_denotation(spelling, federation) == native_denotation(
            spelling, federation
        ), spelling


@pytest.mark.xfail(
    strict=True, reason=reason("strip-protocol-loses-the-osdf-federation")
)
def test_strip_protocol_keeps_the_osdf_federation():
    """pelicanfs's two front doors must denote the same object.

    ``_strip_protocol`` drops the scheme and leaves ``ns/obj``, which
    ``_check_fspath`` then reads as the *host* ``ns``.  So for a
    filesystem bound to OSDF, ``info('osdf://ns/obj')`` resolves while
    ``glob('osdf://ns/obj')``, which strips first, is refused as naming
    another federation.  Bound to ``pelican://ns`` instead, the stripped
    form resolves and silently reads from the wrong federation.

    The native control is ``test_native_path_front_doors_compose``.
    """
    spelling = "osdf://ns/obj"
    direct = pelicanfs_denotation(spelling, "pelican://osg-htc.org")
    composed = pelicanfs_denotation(
        spelling, "pelican://osg-htc.org", via_strip_protocol=True
    )
    assert direct == composed, f"direct={direct!r} via _strip_protocol={composed!r}"


@pytest.mark.xfail(strict=True, reason=reason("path-rejection-exception-class"))
def test_path_rejections_share_an_exception_type():
    """Refusing a path should raise something a caller can catch once.

    ``pelicanfs`` raises from ``PelicanException(RuntimeError)``; the
    native side raises ``ValueError``, which is what fsspec backends and
    the standard library do for a malformed argument.
    """
    with pytest.raises(ValueError):
        pelicanfs_core.PelicanFileSystem.__new__(
            pelicanfs_core.PelicanFileSystem
        )._check_fspath("s3://bucket/key")


@pytest.mark.xfail(strict=True, reason=reason("url-with-no-path-is-empty"))
def test_url_with_no_path_denotes_the_root():
    """``pelican://host`` names the federation root, not the empty path.

    pelicanfs returns ``''``, which is then concatenated into a director
    URL; the native side returns ``'/'``.  ``canonical`` absorbs this,
    so without this test the register entry would be prose with nothing
    behind it.
    """
    fs = PelicanFileSystem.__new__(PelicanFileSystem)
    fs.discovery_url = "pelican://example.org/"
    assert fs._check_fspath("pelican://example.org") == "/"
