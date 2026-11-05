# pelicanfs-native

An [fsspec](https://filesystem-spec.readthedocs.io/) implementation for
[Pelican](https://pelicanplatform.org/) federations, backed by the
native Pelican client.

It wraps `libpelicanclient` — the C interface to the Go Pelican client,
built by [pelican-c](https://github.com/PelicanPlatform/pelican-c) —
through CFFI. Director interaction, cache selection, token discovery,
retries and redirects are all handled by the Go client; this package is
the fsspec surface over it.

## Relationship to `pelicanfs`

[`pelicanfs`](https://github.com/PelicanPlatform/pelicanfs) is a
pure-Python fsspec implementation of the same thing. **`pelicanfs-native`
does not replace it.** Both are supported, and having two independent
implementations of one contract is the point: it makes differential
testing possible, where one implementation is the oracle for the other.

|                | `pelicanfs`               | `pelicanfs-native`                |
| -------------- | ------------------------- | --------------------------------- |
| Engine         | aiohttp + aiowebdav2      | Go Pelican client via CFFI        |
| Install        | pure Python wheel         | compiled; needs `libpelicanclient` |
| fsspec model   | `AsyncFileSystem`         | `AbstractFileSystem` (sync)       |
| Protocols      | `pelican://`, `osdf://`   | `pelican+native://`, `osdf+native://` |

The protocol names differ deliberately. fsspec's entry-point loader
(`process_entries` in `fsspec/__init__.py`) registers with
`clobber=True` and skips same-name duplicates, so two distributions
claiming `pelican` would not raise — one would silently shadow the
other, depending on metadata iteration order. A differential harness
would then compare an implementation with itself and find nothing.

## Installing

`libpelicanclient` must be present at build time. The CFFI extension is
built in API mode, so it `#include`s the real `pelican/client.h` and the
C compiler checks every declaration against it — a signature that drifts
out of sync with pelican-c is a build failure, not a runtime surprise.

```bash
# Build and install the C library
git clone https://github.com/PelicanPlatform/pelican-c
make -C pelican-c install PREFIX="$HOME/.local"

# Build this package against it
PELICAN_C_PREFIX="$HOME/.local" pip install .
```

To build against an uninstalled pelican-c checkout instead:

```bash
PELICAN_C_BUILD_DIR=/path/to/pelican-c pip install -e .
```

## Using

```python
import fsspec

fs = fsspec.filesystem(
    "pelican+native",
    federation_discovery_url="pelican://osg-htc.org",
)
print(fs.ls("/ospool/uc-shared/public/OSG-Staff"))

with fs.open("/ospool/uc-shared/public/OSG-Staff/validation/test.txt", "rb") as fh:
    print(fh.read())
```

A filesystem instance is bound to one federation. Paths may be full
`pelican://` URLs or bare namespace paths; a URL naming a different
federation than the instance is an error, because an fsspec instance
addresses exactly one backend. `fsspec.open("pelican+native://host/ns/obj")`
binds the federation from the URL.

## Caveats

These follow from embedding a Go runtime in CPython, and are worth
knowing before you build on this:

- **No `fork()` after the client initializes.** A forked child
  deadlocks in the Go runtime. `multiprocessing` must use the `spawn`
  start method, and fork-server-based fuzzing harnesses will not work.
  `pytest-xdist` is fine — it spawns.
- **Configuration is process-global.** `pelican_client_init` runs once
  per process and `pelican_config_set` must precede it, so Pelican
  configuration is a property of the process, not of a filesystem
  instance. Asking for a conflicting configuration raises rather than
  silently inheriting the first one. Per-federation settings ride in the
  URL and in per-call options, not in global config.
- Instances are not cached (`cachable = False`), for the same reason.
- The Go runtime installs a `SIGPROF` handler, which collides with
  Python profilers.

## Testing

The suite runs against a real federation launched from the
`pelican-server` binary — a `posixv2` origin and the V2 cache, both on
the pure-Go serving paths, so no XRootD installation is needed.

Mocking HTTP was the alternative and was rejected: both implementations
are full Pelican clients, so a mock would have to model the federation
protocol twice, once per client, and the mock would become the thing
under test.

```bash
# The 'differential' group: pytest, pelicanfs, hypothesis and the
# aiowebdav2 pin. Needs pip >= 25.1 for --group.
pip install -e . --group differential

# Point at a Pelican release (or put the binaries on PATH)
eval "$(scripts/fetch-pelican.sh .pelican-bin >/dev/null && echo \
  export PELICANFS_NATIVE_CLIENT_BINARY=$PWD/.pelican-bin/pelican \
  PELICANFS_NATIVE_SERVER_BINARY=$PWD/.pelican-bin/pelican-server)"

pytest -v
```

CI runs this on Linux and macOS against a pinned Pelican release
(`PELICAN_VERSION` in the workflow), building `libpelicanclient` from
pelican-c `main` so that header drift shows up as a compile error.

TLS verification stays on throughout: the harness hands the federation's
generated CA to the Go client via `PELICAN_SERVER_TLSCACERTIFICATEFILE`
and to Python via `SSL_CERT_FILE`. Disabling verification would hide
exactly the class of bug the suite exists to find.

### The differential oracle

`test/test_differential.py` drives both implementations against the same
federation and asserts they agree. Normalization lives in the harness,
never in either library — each should implement the fsspec contract as
directly as it can, and bending one to match the other's quirks is how a
differential oracle stops finding anything.

Known divergences are recorded in
[`KNOWN_DIVERGENCES.toml`](KNOWN_DIVERGENCES.toml) and pinned by
`xfail(strict=True)`; see [Known divergences](#known-divergences) below.

`PATH_SPELLINGS` in that module is a hand-written corpus of path
spellings. The oracle asserts only that both implementations reach the
same verdict, so a new spelling can be added without deciding up front
what it should mean. Path handling is the axis that has produced real
`pelicanfs` bugs: namespace prefix matching on path boundaries,
trailing-slash handling, and globbing over `pelican://` and `osdf://`
URLs were all recent fixes.

### The fuzzer

That corpus is also the seed for a generative fuzzer, built on
[Hypothesis](https://hypothesis.readthedocs.io/) and run by the ordinary
`pytest` invocation above — there is nothing extra to start.

| Module | Surface | Cost per example |
| ------ | ------- | ---------------- |
| `test/test_fuzz_paths.py` | the pure functions that turn a spelling into the object it denotes | microseconds |
| `test/test_fuzz_operations.py` | `cat_file`, `info`, `exists`, `ls` against the live federation | a network round trip |

`test/path_strategies.py` holds the grammar: schemes (including the
`+native` aliases), hosts with and without ports, and path segments
chosen because some layer — `urlsplit`, `PurePosixPath`, a prefix match,
percent-decoding — treats them specially. Both modules state their
oracle predicate in the module docstring, which matters because the two
implementations' entry points do not have matching signatures and
"agree" therefore has to be defined rather than assumed.

Known divergences are absorbed by a function that names the responsible
`KNOWN_DIVERGENCES.toml` key at the point of absorption, so the fuzzer
fails only on differences nobody has written down. When it does fail it
prints the spelling, the federation and both outcomes, and Hypothesis
has already shrunk the spelling to the smallest one that still shows the
difference.

#### Running the long profile

The default profile is sized for CI: a bounded number of examples and no
per-example deadline, because these tests share a process with a Go
runtime and a federation, so a time limit measures the machine. A `soak`
profile runs the same tests far longer and is selected on the command
line:

```bash
pytest --hypothesis-profile=soak test/test_fuzz_paths.py
```

That is minutes rather than seconds for the pure fuzzer, and much longer
for `test_fuzz_operations.py`, which is real I/O — give it a target:

```bash
pytest --hypothesis-profile=soak -k "fuzz and not operations"
```

Both profiles live in `test/conftest.py`; one knob, `max_examples`,
moves both phases, since the federation-backed tests derive their budget
from it by `NETWORK_BUDGET_DIVISOR`.

A failure found by the soak profile should be turned into a
deterministic test before it is fixed. Hypothesis prints a
`@reproduce_failure` blob, but that is tied to a Hypothesis version;
the shrunk input in the assertion message is not.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Known divergences

Every place the two implementations disagree is recorded in
[`KNOWN_DIVERGENCES.toml`](KNOWN_DIVERGENCES.toml), which is the single
source of truth: `test/test_differential.py` loads it and uses each
entry's summary as the reason on an `xfail(strict=True)`, so an entry
cannot drift from the test that pins it. Two guards keep the register
honest — `test_register_is_well_formed` checks the schema, and
`test_register_has_no_stale_entries` fails if an entry stops being
pinned, so a fixed divergence cannot quietly become folklore.

Because the xfails are strict, the suite stays green while a divergence
lasts and **fails the day it is fixed**. That is the signal to delete
the entry, not a regression.

Six divergences were recorded on the oracle's first run against a real
federation. The most serious: the first `pelicanfs.info()` call on a
filesystem instance succeeds and every later one raises
`FileNotFoundError`, which hits every real caller because fsspec hands
the same cached instance to everyone using the same federation. See the
register for the rest, each with its blame and how to reproduce it.

Separately, and not a divergence: `pip install pelicanfs` is currently
broken. pelicanfs 1.5.0 calls `aiowebdav2`'s `info` and
`list_with_infos`, which aiowebdav2 1.0.0 removed, and the dependency is
declared with no upper bound, so `ls()` and `info()` raise
`AttributeError` on a fresh install. This repo pins `aiowebdav2 <1`.
