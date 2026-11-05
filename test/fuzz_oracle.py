"""Shared oracle vocabulary for the federation-backed fuzzers.

Three ideas live here, used by both :mod:`test_fuzz_names` and
:mod:`test_fuzz_stateful`.

**Ground truth.**  The test origin is ``Origin.StorageType: posixv2``
over a real directory, so after any operation the harness can walk that
directory and see what the federation actually holds.  That is not a
tie-break between two opinions -- it says which implementation is
*wrong*, where a differential comparison only says they differ.  Every
mutation is checked against it.

**Reachability, not exception class.**  The name fuzzer reduces a
failed read to the bare fact of failure.  Both libraries fail on
``semi;colon.txt`` and on ``hash#frag.txt``; they raise different
classes (``PelicanFileNotFoundError`` against ``NoAvailableSource`` or
``FileNotFoundError``), and holding them to a shared class here would
turn every shared wart into a finding.  Which exception a failure
raises is ``path-rejection-exception-class``'s complaint, registered
already; this oracle asks the question underneath it, which is whether
the object can be reached at all.

**Absorption against ground truth, not against a name predicate.**  The
first draft of :func:`explains_exists` tried to decide from the
spelling which names need percent-encoding, and could not: ``amp&eq=1``
and ``at@sign`` survive while ``quote'single`` does not, so the
predicate was a list of observations pretending to be a rule.  Keying
on the disagreement itself -- the object is on disk, one library finds
it, the other says it is not there -- needs no such rule and cannot
drift.
"""

from __future__ import annotations

from typing import Any, Callable

# Names whose URL form the Go client refuses to parse.  Observed, and
# narrow on purpose: a literal '%' makes an invalid escape sequence
# ("invalid URL escape \"%.t\"") and a control character is rejected
# outright ("invalid control character in URL").  Everything else the
# corpus holds either works or fails on both sides.
def go_cannot_parse(name: str) -> bool:
    return "%" in name or any(ord(c) < 0x20 for c in name)


def reach(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[str, Any]:
    """Run an operation and reduce a failure to the fact of failing.

    Returns ``("ok", value)`` or ``("raise", <exception>)``.  Compare
    only the first element when the question is reachability.
    """
    try:
        return ("ok", fn(*args, **kwargs))
    except Exception as exc:  # noqa: BLE001 -- failing is the result
        return ("raise", exc)


def report(label: str, native: Any, pure: Any, truth: Any = None) -> str:
    lines = [f"\n{label}", f"native     {native!r}", f"pelicanfs  {pure!r}"]
    if truth is not None:
        lines.append(f"on disk    {truth!r}")
    return "\n".join(lines)


def explains_exists(on_disk: bool, native: tuple[str, Any], pure: tuple[str, Any]) -> str | None:
    """Name the registered divergence an ``exists`` disagreement belongs to."""
    if pure[0] == "raise":
        # exists() answers a question; pelicanfs lets the refusal escape.
        return "exists-raises-on-an-unusable-path"
    if on_disk and native == ("ok", True) and pure[1] is False:
        return "exists-ignores-encoding"
    return None


def explains_read(name: str, native: tuple[str, Any], pure: tuple[str, Any]) -> str | None:
    """Name the registered divergence a read disagreement belongs to."""
    if native[0] == "raise" and pure[0] == "ok" and go_cannot_parse(name):
        return "native-rejects-a-literal-percent-in-a-name"
    return None
