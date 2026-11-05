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
pip install -e . pytest pytest-timeout pelicanfs "aiowebdav2<1"

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

Known divergences are declared in `KNOWN_DIVERGENCES` and marked
`xfail(strict=True)`, so the suite stays green while a divergence lasts
and fails loudly the day it is fixed and the entry goes stale.

`PATH_SPELLINGS` in that module is a hand-written corpus of path
spellings — the seed for a generative fuzzer. The oracle asserts only
that both implementations reach the same verdict, so a new spelling can
be added without deciding up front what it should mean. Path handling is
the axis that has produced real `pelicanfs` bugs: namespace prefix
matching on path boundaries, trailing-slash handling, and globbing over
`pelican://` and `osdf://` URLs were all recent fixes.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Findings so far

The oracle found these on its first run against a real federation. Each
is recorded in `KNOWN_DIVERGENCES` and pinned by an `xfail(strict=True)`
test, so the suite stays green until the divergence is fixed and then
fails to tell us the entry is stale.

1. **`pelicanfs.info()` poisons its own instance.** The first `info()`
   call on a `PelicanFileSystem` succeeds; every later one on that
   instance raises `FileNotFoundError`. Each object stats fine as the
   first call on a genuinely fresh instance and fails as the second.
   This bites every real caller, because fsspec keys its instance cache
   on the storage options and hands the same instance to everyone using
   the same federation.
2. **`pelicanfs.info()["name"]` is not addressable.** It returns the
   endpoint path it was answered from
   (`/api/v1.0/origin/data/ns/obj`) rather than the namespace path. That
   name cannot be passed back to `open()` or `ls()`, which the fsspec
   contract requires. The underlying library echoes the same endpoint
   path from `stat`, so this is a wart passed through rather than
   normalized.
3. **`pelicanfs.ls()` crashes on a collection containing a
   subdirectory**, with `ValueError: invalid literal for int() with base
   10: ''` — it calls `int(item["size"])` on every entry, and a
   collection's PROPFIND size property is empty.
4. **`pip install pelicanfs` is currently broken.** pelicanfs 1.5.0
   calls `aiowebdav2`'s `info` and `list_with_infos`, which aiowebdav2
   1.0.0 removed, and the dependency is declared with no upper bound.
   `ls()` and `info()` raise `AttributeError` on a fresh install. This
   repo pins `aiowebdav2 <1` as a workaround.
5. **A read entirely past EOF** returns `b''` from the native client and
   raises from pelicanfs. fsspec does not pin this — HTTP answers 416
   while a local filesystem returns `b''` — so it needs a decision
   before either side is called wrong.
6. **`info()` never reports a collection** from pelicanfs: `type` is
   hardcoded to `"file"`.

Divergence 2 is also why `pelicanfs_native` derives entry names from the
path the caller asked for rather than from what the library echoes; see
`_entry` in `core.py`.
