"""The containment controls, exercised rather than asserted.

``fuzz_export`` claims that a generated object name cannot become a
local path outside the session root.  That claim is the only thing
standing between a fuzzer that deliberately generates ``..`` and a
developer's home directory, and an untested safety control is a
comment.

These tests need no federation and run in milliseconds.
"""

from __future__ import annotations

import os

import pytest

from fuzz_export import (
    ExportObject,
    build_export,
    contained,
    content_for,
    load_manifest,
    opaque_local_name,
    require_contained,
    tripwire_violations,
)


# --------------------------------------------------------------------- #
# contained()                                                           #
# --------------------------------------------------------------------- #


def test_contained_accepts_the_root_and_its_children(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    assert contained(tmp_path, tmp_path)
    assert contained(tmp_path, tmp_path / "a")
    assert contained(tmp_path, tmp_path / "a" / "b")


def test_contained_rejects_a_sibling_with_a_shared_prefix(tmp_path):
    """The reason this is not a bare ``startswith``.

    ``/tmp/foo2`` starts with ``/tmp/foo`` and is not inside it. A
    prefix test without the separator passes it, which is the classic
    way a containment check is wrong in a way nobody notices.
    """
    root = tmp_path / "foo"
    sibling = tmp_path / "foo2"
    root.mkdir()
    sibling.mkdir()
    assert str(sibling).startswith(str(root)), "the trap this guards against"
    assert not contained(root, sibling)


def test_contained_rejects_traversal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside").mkdir()
    assert not contained(root, root / ".." / "outside")
    assert not contained(root, "/etc/passwd")


def test_contained_follows_symlinks(tmp_path):
    """A symlink out of the root is out of the root.

    ``realpath`` on both sides is what makes this true; a purely
    lexical check would call the link an ordinary child.
    """
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "outside"
    target.mkdir()
    link = root / "escape"
    link.symlink_to(target)
    assert not contained(root, link)
    assert not contained(root, link / "file.txt")


def test_require_contained_raises_and_names_both_paths(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(AssertionError) as caught:
        require_contained(root, "/etc/passwd")
    assert "/etc/passwd" in str(caught.value)
    assert str(root) in str(caught.value)


# --------------------------------------------------------------------- #
# The primary control: names never become paths                        #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "hostile",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "..",
        "a/../../../b",
        "C:\\Windows\\system32",
        "\\\\server\\share",
        "sub/../../out.txt",
    ],
)
def test_an_opaque_local_name_cannot_traverse(tmp_path, hostile):
    """Whatever the remote name is, the local one is 32 hex digits.

    This is the control that matters, because it makes traversal
    unrepresentable instead of merely detected. The test is the
    demonstration: joining the *remote* name escapes, joining the
    opaque one cannot.
    """
    local = opaque_local_name(hostile)
    assert len(local) == 32 and all(c in "0123456789abcdef" for c in local)
    assert contained(tmp_path, tmp_path / local)
    # And the thing it replaces does not hold:
    naive = os.path.join(str(tmp_path), hostile)
    if hostile.startswith("/") or ".." in hostile:
        assert not contained(tmp_path, naive), (
            "the naive join was supposed to escape; if it no longer does, "
            "this test has stopped demonstrating anything"
        )


def test_opaque_local_names_are_stable_and_distinct():
    assert opaque_local_name("a") == opaque_local_name("a")
    assert opaque_local_name("a") != opaque_local_name("b")
    assert opaque_local_name("a", ".1").endswith(".1")


# --------------------------------------------------------------------- #
# build_export                                                          #
# --------------------------------------------------------------------- #


def test_build_export_refuses_a_traversal_name(tmp_path):
    """A manifest name that escapes is dropped, not created.

    The corpus does not contain one -- names that escape belong in the
    pure path tests, where nothing is dispatched -- but the export
    builder is the one place a real name reaches the filesystem, so it
    is the one place that has to refuse.
    """
    root = tmp_path / "export"
    outside = tmp_path / "outside.txt"
    objects = [
        ExportObject("good.txt", 4, ""),
        ExportObject("../outside.txt", 4, ""),
        ExportObject("sub/../../escape.txt", 4, ""),
    ]
    realized, dropped = build_export(root, objects)
    assert [o.name for o in realized] == ["good.txt"]
    assert sorted(dropped) == ["../outside.txt", "sub/../../escape.txt"]
    assert not outside.exists()
    assert not (tmp_path / "escape.txt").exists()
    assert sorted(p.name for p in root.rglob("*")) == ["good.txt"]


def test_build_export_does_not_let_two_names_collide(tmp_path):
    """On a case-insensitive volume, one of a pair must be dropped whole.

    Letting the second write land on the first would leave a survivor
    answering with the wrong object's bytes, and every read of it
    would look like a transfer bug rather than a local filesystem
    quirk.
    """
    root = tmp_path / "export"
    objects = [ExportObject("Name.txt", 4, ""), ExportObject("name.txt", 9, "")]
    realized, dropped = build_export(root, objects)
    for obj in realized:
        assert (root / obj.name).read_bytes() == obj.content
    assert len(realized) + len(dropped) == 2


def test_build_export_materializes_the_real_manifest(tmp_path):
    """The checked-in corpus builds, with at most the case pair lost."""
    objects = load_manifest()
    realized, dropped = build_export(tmp_path / "export", objects)
    assert len(realized) >= len(objects) - 1, dropped
    for obj in realized:
        assert (tmp_path / "export" / obj.name).read_bytes() == obj.content


def test_content_identifies_the_object():
    """Bytes are derived from the name, so a mix-up is visible.

    A constant filler would make a read of the wrong object compare
    equal to a read of the right one.
    """
    assert content_for("a", 0) == b""
    assert len(content_for("a", 100)) == 100
    assert content_for("a", 100) != content_for("b", 100)
    assert content_for("a", 100) == content_for("a", 100)


# --------------------------------------------------------------------- #
# The tripwire                                                          #
# --------------------------------------------------------------------- #


def _tripwire(tmp_path):
    canary = tmp_path / "canary.txt"
    payload = b"canary\n"
    canary.write_bytes(payload)
    (tmp_path / "session-root").mkdir()
    before = {p.name: p.is_dir() for p in tmp_path.iterdir()}
    return canary, payload, before


def test_the_tripwire_is_quiet_when_nothing_escaped(tmp_path):
    canary, payload, before = _tripwire(tmp_path)
    # Work inside the session root, as the suite is supposed to.
    (tmp_path / "session-root" / "whatever.txt").write_bytes(b"x")
    (tmp_path / "a-new-pytest-tmpdir").mkdir()
    assert tripwire_violations(tmp_path, canary, payload, before) == []


def test_the_tripwire_notices_a_modified_canary(tmp_path):
    canary, payload, before = _tripwire(tmp_path)
    canary.write_bytes(b"clobbered")
    assert "modified" in " ".join(tripwire_violations(tmp_path, canary, payload, before))


def test_the_tripwire_notices_a_deleted_canary(tmp_path):
    canary, payload, before = _tripwire(tmp_path)
    canary.unlink()
    assert "deleted" in " ".join(tripwire_violations(tmp_path, canary, payload, before))


def test_the_tripwire_notices_a_vanished_neighbour(tmp_path):
    canary, payload, before = _tripwire(tmp_path)
    os.rmdir(tmp_path / "session-root")
    problems = tripwire_violations(tmp_path, canary, payload, before)
    assert any("session-root" in p for p in problems), problems
