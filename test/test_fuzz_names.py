"""Differential fuzzing of the object *names*, not just the spellings.

:mod:`test_fuzz_paths` fuzzes how a caller writes a path.  This module
fuzzes what the federation is asked to hold: the export is built from
``test/corpus/export.toml``, a checked-in manifest of names chosen
because some layer between the caller and the origin reads each one as
syntax -- a space, a bare ``%``, ``#``, ``?``, ``+``, ``;``, a glob
metacharacter, a control character, NFC against NFD, 250 bytes of
``a``, five levels of nesting, and objects from zero to 64 KiB.

Both implementations are then asked to address every object in it, and
the posix export directory on disk is the arbiter for who is right.

The corpus is checked in rather than generated per run, and that is the
point of it: a differential harness whose inputs are redrawn every
session cannot reproduce its own findings.  A name that breaks
something goes into the manifest and breaks it on every machine
afterwards, including CI -- which is the persistent-corpus half of
"fuzzing" that a Hypothesis example database, local and gitignored,
does not give.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import NETWORK_BUDGET_DIVISOR
from fuzz_export import load_manifest
from fuzz_oracle import explains_exists, explains_read, reach, report
from test_differential import normalize, reason

pytestmark = pytest.mark.differential

NETWORK_EXAMPLES = max(5, settings().max_examples // NETWORK_BUDGET_DIVISOR)

# Loaded at import time, from the checked-in file, so the strategy is
# the same on every machine and a shrunk failure names an object that
# everyone has.  Ordered as the manifest is -- controls first -- so
# Hypothesis shrinks towards the boring names and a surviving failure
# is about the interesting one.
MANIFEST = load_manifest()
BY_NAME = {o.name: o for o in MANIFEST}


def object_names() -> st.SearchStrategy[str]:
    return st.sampled_from([o.name for o in MANIFEST])


def _present(federation, name: str):
    """The manifest object, or skip if the local filesystem ate the name.

    A case-insensitive volume (macOS's default) cannot hold
    ``CaseName.txt`` and ``casename.txt`` at once.  The casualty list is
    asserted to be exactly that pair in
    :func:`test_the_export_is_what_the_manifest_asked_for`, so skipping
    here cannot quietly hollow the suite out.
    """
    if name in federation.dropped_objects:
        pytest.skip(f"{name!r} did not survive this filesystem")
    return BY_NAME[name]


# --------------------------------------------------------------------- #
# The export itself                                                     #
# --------------------------------------------------------------------- #


def test_the_export_is_what_the_manifest_asked_for(federation):
    """The generated export really holds the generated names.

    Without this, a manifest that failed to materialize would leave the
    name fuzzer sweeping three objects and reporting green -- the same
    failure mode as ``test_the_fuzzer_reaches_every_shape`` next door,
    which exists because the path fuzzer once generated nothing
    interesting and said so in a passing run.
    """
    assert len(federation.objects) >= len(MANIFEST) - 1, (
        f"only {len(federation.objects)} of {len(MANIFEST)} manifest objects "
        f"were created; dropped {federation.dropped_objects}"
    )
    # The only casualty this harness tolerates is a case collision,
    # which is the local volume's doing and not Pelican's.
    folded = {n.lower() for n in federation.dropped_objects}
    survivors = {o.name.lower() for o in federation.objects}
    assert folded <= survivors, (
        f"{federation.dropped_objects} were dropped for a reason other than "
        f"a case-insensitive filesystem"
    )
    on_disk = {
        str(p.relative_to(federation.fuzz_export_dir))
        for p in federation.fuzz_export_dir.rglob("*")
        if p.is_file()
    }
    assert {o.name for o in federation.objects} <= on_disk


def test_the_manifest_covers_the_classes_it_claims(federation):
    """The corpus must actually contain the shapes the docstring sells."""
    names = {o.name for o in MANIFEST}
    checks = {
        "a space": any(" " in n for n in names),
        "a bare percent": any("%" in n for n in names),
        "a hash": any("#" in n for n in names),
        "a question mark": any("?" in n for n in names),
        "a plus": any("+" in n for n in names),
        "non-ASCII": any(any(ord(c) > 127 for c in n) for n in names),
        "a long name": any(len(n) > 200 for n in names),
        "case-only variants": len({n.lower() for n in names}) < len(names),
        "depth >= 4": any(n.count("/") >= 4 for n in names),
        "an empty object": any(o.size == 0 for o in MANIFEST),
        "a multi-block object": any(o.size > 64 * 1024 for o in MANIFEST),
    }
    assert all(checks.values()), [k for k, v in checks.items() if not v]


# --------------------------------------------------------------------- #
# Reads                                                                 #
# --------------------------------------------------------------------- #


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(object_names())
def test_cat_file_agrees_on_every_name(native_fs, new_pelicanfs, federation, name):
    """Reading an object must give its bytes, whatever it is called.

    The expected bytes come from the export directory, so neither
    library's opinion is the reference.
    """
    obj = _present(federation, name)
    path = federation.fuzz_path(name)
    expected = (federation.fuzz_export_dir / name).read_bytes()
    assert expected == obj.content

    native = reach(native_fs.cat_file, path)
    pure = reach(new_pelicanfs().cat_file, path)
    if native[0] == pure[0] == "ok":
        assert native[1] == pure[1] == expected, report(path, native, pure, expected)
        return
    if native[0] == pure[0]:
        # Both refuse. Which exception each raises is
        # path-rejection-exception-class's business, not this test's.
        return
    key = explains_read(name, native, pure)
    assert key is not None, (
        f"unexplained divergence reading {name!r}" + report(path, native, pure, expected)
    )


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(object_names())
def test_exists_agrees_on_every_name(native_fs, new_pelicanfs, federation, name):
    _present(federation, name)
    path = federation.fuzz_path(name)
    on_disk = (federation.fuzz_export_dir / name).is_file()
    native = reach(native_fs.exists, path)
    pure = reach(new_pelicanfs().exists, path)
    if native == pure:
        return
    key = explains_exists(on_disk, native, pure)
    assert key is not None, (
        f"unexplained divergence on exists({name!r})"
        + report(path, native, pure, on_disk)
    )


@settings(max_examples=NETWORK_EXAMPLES, deadline=None)
@given(object_names())
def test_info_agrees_on_size_for_every_name(native_fs, new_pelicanfs, federation, name):
    """``info()`` must report the size the object has on disk.

    A fresh pelicanfs per example: its ``info`` is poisoned by any
    earlier operation on the same instance (``info-is-stateful``).
    """
    _present(federation, name)
    path = federation.fuzz_path(name)
    expected = (federation.fuzz_export_dir / name).stat().st_size
    native = reach(native_fs.info, path)
    pure = reach(new_pelicanfs().info, path)
    if native[0] == pure[0] == "ok":
        assert normalize(native[1])["size"] == normalize(pure[1])["size"] == expected, (
            report(path, native[1], pure[1], expected)
        )
        return
    if native[0] == pure[0]:
        return
    # info() has the same unencoded-path fault as exists(): pelicanfs
    # hands urlparse(path).path straight to the WebDAV client, so every
    # name needing percent-encoding stats as missing. Absorbed by the
    # same register key and deliberately NOT given a pin of its own:
    # info()'s WebDAV behaviour is being rewritten upstream and
    # findings against it are on hold. The exists() half, which is not
    # part of that rewrite's surface, carries the pin.
    key = explains_exists(
        (federation.fuzz_export_dir / name).is_file(),
        ("ok", native[0] == "ok"),
        ("ok", pure[0] == "ok"),
    )
    assert key is not None, (
        f"info() disagrees on whether {name!r} exists" + report(path, native, pure)
    )


# --------------------------------------------------------------------- #
# Pins                                                                  #
# --------------------------------------------------------------------- #


@pytest.mark.xfail(strict=True, reason=reason("exists-ignores-encoding"))
def test_exists_is_true_for_an_object_it_can_read(new_pelicanfs, federation):
    """exists() must not say no about an object the same instance reads.

    ``with space.txt`` is the simplest case in the corpus: one space,
    nothing else unusual, present on disk, read correctly by
    ``cat_file`` -- and ``exists()`` returns False.
    """
    name = "with space.txt"
    path = federation.fuzz_path(name)
    assert (federation.fuzz_export_dir / name).is_file()
    assert new_pelicanfs().cat_file(path) != b"", "the control: it is readable"
    assert new_pelicanfs().exists(path) is True


@pytest.mark.xfail(
    strict=True, reason=reason("native-rejects-a-literal-percent-in-a-name")
)
def test_native_reads_a_name_holding_a_literal_percent(native_fs, federation):
    """One object must not be statable and unreadable by one library.

    pelicanfs reads both of these; the native client stats them, says
    they exist, and then cannot open them -- so this one is its own
    bug and not pelicanfs's.
    """
    for name in ("literal%.txt", "a%zz.txt"):
        path = federation.fuzz_path(name)
        assert native_fs.info(path)["size"] > 0, f"the control: {name} stats fine"
        assert native_fs.exists(path) is True, f"the control: {name} exists"
        assert native_fs.cat_file(path) == (federation.fuzz_export_dir / name).read_bytes()


def _self_inconsistent(fs_for, federation) -> list[str]:
    """Objects a filesystem says are there and then refuses to read.

    Self-consistency, asked of one implementation at a time, so the
    answer does not depend on the other being right.
    """
    wrong = []
    for obj in federation.objects:
        path = federation.fuzz_path(obj.name)
        try:
            here = fs_for().exists(path) is True
        except Exception:  # noqa: BLE001 -- exists-raises-on-an-unusable-path
            continue
        if not here:
            continue
        try:
            fs_for().cat_file(path)
        except Exception:  # noqa: BLE001 -- reachability is the result
            wrong.append(obj.name)
    return wrong


@pytest.mark.xfail(
    strict=True, reason=reason("native-rejects-a-literal-percent-in-a-name")
)
def test_neither_side_claims_an_object_it_cannot_read(
    native_fs, new_pelicanfs, federation
):
    """Saying an object is there and then refusing it is one bug, twice.

    Measured on the generated export (34 objects on a case-sensitive
    filesystem): the native side is inconsistent about seven of them,
    pelicanfs about two -- ``pct%25.txt`` and ``pct%20dir/child.txt``,
    names that already look percent-encoded, where neither client
    round-trips the spelling and the fault may well be the
    federation's.  Those two are therefore a shared wart rather than a
    divergence, and what this pins is the five the native side adds on
    its own: ``literal%.txt``, ``a%zz.txt``, ``hash#frag.txt``,
    ``question?q.txt`` and ``tab\tname.txt``.

    The first draft of this test asserted pelicanfs was consistent and
    was simply wrong -- it had only been run on a case-insensitive
    volume where the probe stopped at the first mismatch.  The sets
    are both measured now rather than one being assumed clean.
    """
    native = set(_self_inconsistent(lambda: native_fs, federation))
    pure = set(_self_inconsistent(new_pelicanfs, federation))
    assert not (native - pure), (
        f"the native side claims and then refuses {sorted(native - pure)}, "
        f"which pelicanfs handles consistently (it is inconsistent only "
        f"about {sorted(pure)})"
    )


@pytest.mark.xfail(
    strict=True, reason=reason("native-listing-names-are-percent-encoded")
)
def test_native_listing_names_are_addressable(native_fs, federation):
    """A name ls() returns must be one the same filesystem accepts back."""
    for name in native_fs.ls(federation.fuzz_namespace, detail=False):
        if native_fs.isdir(name):
            continue
        assert native_fs.exists(name), name
