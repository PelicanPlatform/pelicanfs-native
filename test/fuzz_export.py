"""The generated export, and the containment rules that make it safe.

The federation's export used to be three objects written by hand, so an
object *name* was never an input to anything.  This module builds the
export from ``test/corpus/export.toml`` instead, which turns the name
into a fuzzable axis: both implementations are asked to address every
object in the manifest, and the manifest is full of names that some
layer between the caller and the origin reads as syntax.

Safety
------

Generating hostile names creates one genuinely dangerous operation, and
it is not on the remote side -- that is a throwaway federation on
loopback.  It is the harness turning a *remote* name into a *local*
path.  ``os.path.join(dest, "/etc/passwd")`` is ``"/etc/passwd"`` and
``Path("/a") / "/etc/passwd"`` is ``Path("/etc/passwd")``: one generated
``..`` or leading separator and a download destination is anywhere on
the disk.

Three rules, in order of precedence, and the first is the one that
matters:

1. **Never derive a local path from a generated name.**  Every local
   file the harness creates for a generated object is named by
   :func:`opaque_local_name`, a hash of the remote name.  Traversal
   then is not filtered out, it is unrepresentable.
2. Where a real name must reach the filesystem -- building the export
   itself, which has to create the hostile names on disk -- call
   :func:`contained` before opening and again after creating.  It
   compares ``realpath``s with a trailing separator, because a bare
   ``startswith`` lets ``/tmp/foo2`` pass as inside ``/tmp/foo``, and
   it is re-checked after creation because a symlink can appear in
   between.
3. **Nothing is filtered out of the corpus.**  ``..``, a leading
   separator and a NUL are exactly the inputs worth sending to the
   remote side.  Filtering them would hide the bug class the fuzzer
   exists to find; containment is what keeps the harness safe, and the
   two are not interchangeable.
"""

from __future__ import annotations

import hashlib
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

CORPUS = Path(__file__).resolve().parent / "corpus" / "export.toml"


@dataclass(frozen=True)
class ExportObject:
    """One object in the generated export."""

    name: str
    size: int
    note: str

    @property
    def content(self) -> bytes:
        return content_for(self.name, self.size)


def content_for(name: str, size: int) -> bytes:
    """Bytes derived from the name, so content identifies the object.

    A read that returns the wrong object's bytes is then a visible
    failure rather than two identical buffers comparing equal, which is
    what a constant filler would give.
    """
    if size == 0:
        return b""
    seed = hashlib.sha256(name.encode("utf-8", "surrogatepass")).digest()
    return (seed * (size // len(seed) + 1))[:size]


def load_manifest(path: Path = CORPUS) -> list[ExportObject]:
    raw = tomllib.loads(path.read_text())
    return [
        ExportObject(name=o["name"], size=int(o["size"]), note=o.get("note", ""))
        for o in raw["object"]
    ]


# --------------------------------------------------------------------- #
# Containment                                                           #
# --------------------------------------------------------------------- #


def contained(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> bool:
    """Whether ``candidate`` resolves to ``root`` itself or inside it.

    ``realpath`` on both sides, and the prefix test carries the
    separator: ``/tmp/foo2`` must not count as inside ``/tmp/foo``.
    """
    real_root = os.path.realpath(root)
    real_candidate = os.path.realpath(candidate)
    return real_candidate == real_root or real_candidate.startswith(real_root + os.sep)


def require_contained(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> str:
    if not contained(root, candidate):
        raise AssertionError(
            f"refusing to touch {str(candidate)!r}: it resolves to "
            f"{os.path.realpath(candidate)!r}, outside {os.path.realpath(root)!r}"
        )
    return str(candidate)


def opaque_local_name(remote_name: str, suffix: str = "") -> str:
    """A local file name for a remote object, carrying none of its spelling.

    This is the primary traversal control: the hostile spelling stays
    on the remote side, and what reaches the local filesystem is 32 hex
    digits.  Stable across runs, so a failure names the same file.
    """
    digest = hashlib.sha256(remote_name.encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:32] + suffix


# --------------------------------------------------------------------- #
# Building the export                                                   #
# --------------------------------------------------------------------- #


def build_export(root: Path, objects: list[ExportObject]) -> tuple[list[ExportObject], list[str]]:
    """Materialize the manifest under ``root``.

    Returns the objects that really exist afterwards and the names that
    did not survive.  A name can fail to survive for two reasons, and
    both are the local filesystem's doing rather than Pelican's:

    * the OS refuses it outright (``OSError``);
    * the OS accepts it and stores something else.  macOS's default
      APFS volume is case-insensitive, so ``casename.txt`` lands on top
      of ``CaseName.txt``; it also normalizes nothing, so the NFC/NFD
      pair does survive there.

    The survivors are what the session advertises, so a test never asks
    for an object the export does not have.  ``test_the_export_is_built``
    asserts the casualties are only ever the case-variant pair, which is
    what keeps a silent mass drop -- an export of two objects and a
    green suite -- from passing for a pass.
    """
    root.mkdir(parents=True, exist_ok=True)
    realized: list[ExportObject] = []
    dropped: list[str] = []
    for obj in objects:
        target = root / obj.name
        try:
            require_contained(root, target.parent)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Re-check after creation: a symlink could have appeared.
            require_contained(root, target.parent)
            if target.exists():
                # Two manifest names collided in the filesystem's eyes.
                # Leave the first one's bytes alone rather than writing
                # this one's over them, or the survivor would answer with
                # the wrong content and every read of it would look like
                # a transfer bug.
                raise FileExistsError(obj.name)
            target.write_bytes(obj.content)
            require_contained(root, target)
        except (OSError, ValueError, AssertionError):
            dropped.append(obj.name)
            continue
        realized.append(obj)

    # A name the OS accepted may still not be the name that landed, and
    # the bytes under it may not be this object's: ask the directory
    # what it holds rather than trusting write().
    survivors = []
    for obj in realized:
        target = root / obj.name
        try:
            exact = str(target.relative_to(root)) in {
                str(p.relative_to(root)) for p in target.parent.iterdir()
            }
            if exact and target.read_bytes() == obj.content:
                survivors.append(obj)
                continue
        except OSError:
            pass
        dropped.append(obj.name)
    return survivors, sorted(dropped)


# --------------------------------------------------------------------- #
# The tripwire                                                          #
# --------------------------------------------------------------------- #


def tripwire_violations(
    outside: Path, canary: Path, payload: bytes, before: dict[str, bool]
) -> list[str]:
    """What changed just outside the session root, if anything.

    A separate function and not an inline assertion in the fixture so
    that it can be unit-tested.  The containment argument in this
    module is only as good as the thing that would notice it being
    wrong, and a check nobody has ever seen fail is not that.
    """
    problems = []
    if not canary.exists():
        problems.append(f"the canary at {canary} was deleted")
    elif canary.read_bytes() != payload:
        problems.append(f"the canary at {canary} was modified")
    try:
        after = {p.name: p.is_dir() for p in outside.iterdir()}
    except OSError as exc:
        return [*problems, f"{outside} is no longer readable: {exc}"]
    vanished = sorted(n for n, kind in before.items() if after.get(n) != kind)
    if vanished:
        problems.append(
            f"entries just outside the session root changed or disappeared: "
            f"{vanished} under {outside}"
        )
    return problems
