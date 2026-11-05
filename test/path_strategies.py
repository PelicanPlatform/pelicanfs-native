"""Hypothesis strategies over the grammar of Pelican path spellings.

The fuzzer's job is to generate things a *caller* might plausibly type
or construct, not arbitrary bytes.  Random text finds encoding bugs;
what has actually broken ``pelicanfs`` is structural -- namespace prefix
matching on a path boundary, a trailing slash surviving or not, a
``pelican://`` URL reaching a code path that expected a bare path.  So
the grammar here is explicit: a spelling is a scheme, optionally a host,
and a path built from segments and separators, with every part drawn
from a list of atoms chosen because something downstream treats it
specially.

Atoms are ordered simplest-first throughout.  Hypothesis shrinks
``sampled_from`` towards index 0 and ``lists`` towards the empty list,
so the ordering is what turns a failure into a minimal, readable bug
report rather than a wall of noise.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from hypothesis import strategies as st

CORPUS = Path(__file__).resolve().parent / "corpus" / "path_spellings.toml"


def corpus_spellings() -> list[str]:
    """The checked-in corpus of interesting spellings.

    Every shrunk counterexample the fuzzer has produced, and one
    spelling per register entry.  Hypothesis's own example database is
    a local, gitignored cache -- a find on one laptop is not
    reproducible on another, let alone in CI -- so anything worth
    keeping is kept here instead.
    """
    raw = tomllib.loads(CORPUS.read_text())
    return [entry["value"] for entry in raw["spelling"]]


CORPUS_SPELLINGS = corpus_spellings()

# Schemes.  The ``+native`` aliases exist because the two distributions
# must not claim the same fsspec protocol name (see the README); a
# caller who writes one means the same object as the plain spelling.
SCHEMES = [
    "",
    "pelican",
    "osdf",
    "pelican+native",
    "osdf+native",
]

# Hosts.  A Pelican federation is named by a hostname and optionally a
# port; the bracketed and userinfo forms are here because urlsplit
# accepts them and a hand-rolled splitter usually does not.
HOSTS = [
    "example.org",
    # The OSDF discovery host, so that an osdf:// spelling can name the
    # federation the filesystem under test is bound to; without it every
    # osdf:// case is rejected as foreign and the oracle sees nothing.
    "osg-htc.org",
    "example.org:8443",
    "localhost",
    "h",
    "EXAMPLE.ORG",
    "[::1]:8443",
    "user:pass@example.org",
    "xn--bcher-kva.example",
    "bücher.example",
]

# Path segments.  Each of these is here because some layer -- urlsplit,
# PurePosixPath, a prefix match, percent-decoding, a filesystem -- gives
# it a meaning the next layer may not share.
SEGMENTS = [
    "a",
    "b",
    "",            # an empty segment, i.e. a doubled separator
    ".",
    "..",
    "...",
    "obj.txt",
    ".hidden",
    "a b",          # a literal space
    "a+b",          # '+' is a space only in a query, not in a path
    "%20",          # a correctly encoded space
    "%2F",          # an encoded separator: decoding it changes the shape
    "%2f",
    "%",            # a stray percent
    "%zz",          # malformed percent-encoding
    "%c3%a9",       # UTF-8 'é', encoded
    "é",            # NFC
    "é",           # NFD: the same grapheme, a different string
    "Ａ",           # fullwidth 'A', which NFKC would fold to 'A'
    "a?q=1",        # a query marker inside what the caller means as a name
    "a#f",          # likewise a fragment marker
    "a;p=1",        # an RFC 3986 path parameter
    "a:b",          # a colon, which makes a relative path look schemed
    "a\\b",         # a backslash, which is not a separator here
    "\t",
    "\n",
    " ",
    " ",       # non-breaking space
    "a" * 300,      # a long segment
]

SEPARATORS = ["/", "//", "///"]


@st.composite
def namespace_paths(draw, *, min_size: int = 0, max_size: int = 4) -> str:
    """A path body: segments joined by one or more separators.

    Leading and trailing separators are drawn independently of the
    segments, because "is this rooted" and "does this end in a slash"
    are the two properties that path handling most often gets wrong and
    they must be reachable in isolation.
    """
    segments = draw(st.lists(st.sampled_from(SEGMENTS), min_size=min_size, max_size=max_size))
    seps = [draw(st.sampled_from(SEPARATORS)) for _ in range(max(len(segments) - 1, 0))]
    body = "".join(
        seg + (seps[i] if i < len(seps) else "") for i, seg in enumerate(segments)
    )
    leading = draw(st.sampled_from(["/", "", "//"]))
    trailing = draw(st.sampled_from(["", "/", "//"]))
    return leading + body + trailing


@st.composite
def generated_spellings(draw) -> str:
    """A whole path spelling, as a caller might write it.

    Covers the four shapes that reach these functions in the wild: a
    bare namespace path, a ``scheme://host/path`` URL, the
    ``scheme:///path`` form that names no host, and the schemeless
    ``host/path`` form that libraries such as xarray construct.
    """
    scheme = draw(st.sampled_from(SCHEMES))
    path = draw(namespace_paths())
    if not scheme:
        # Schemeless: either rooted (a namespace path) or host-first.
        if draw(st.booleans()):
            return path if path.startswith("/") else "/" + path
        host = draw(st.sampled_from(HOSTS))
        return host + (path if path.startswith("/") else "/" + path)
    # authority_form=False produces scheme:///path -- no host at all.
    if draw(st.booleans()):
        body = path if (path.startswith("/") or not path) else "/" + path
        return f"{scheme}://{body}"
    host = draw(st.sampled_from(HOSTS))
    return f"{scheme}://{host}" + path


def federation_hosts() -> st.SearchStrategy[str]:
    """A host to bind the filesystem under test to."""
    return st.sampled_from(HOSTS)


def spellings() -> st.SearchStrategy[str]:
    """The grammar, seeded from the checked-in corpus.

    The corpus comes first in the union so that Hypothesis, which
    shrinks a ``one_of`` towards its first branch, reduces a failure to
    a corpus entry where one will do -- a known-interesting spelling
    with a note attached beats an equivalent one the generator happened
    to build.  It also means the search starts from inputs already
    known to matter instead of rediscovering them every run.
    """
    return st.one_of(st.sampled_from(CORPUS_SPELLINGS), generated_spellings())
