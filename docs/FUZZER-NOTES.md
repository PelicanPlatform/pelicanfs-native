# Fuzzer working notes

Working notes from building the differential fuzzer (branch `fuzzer`).
The README has the user-facing description; this file records what was
measured, what was decided and why, and the dead ends.

## What was built

| File | What it is |
| ---- | ---------- |
| `test/path_strategies.py` | the Hypothesis grammar: schemes, hosts, segments, separators |
| `test/test_fuzz_paths.py` | phase 1, pure-function path fuzzing |
| `test/test_fuzz_operations.py` | phase 2, federation-backed operation fuzzing |
| `test/conftest.py` | the `ci` and `soak` Hypothesis profiles |

## The oracle predicate, and why it is what it is

The two implementations do not have matching signatures, so "agree" had
to be defined.

What a caller depends on is **denotation**: for a filesystem bound to
federation `F`, which object does spelling `S` name, or is `S` refused?
Each side reduces to `("ok", <canonical namespace path>)` or
`("reject", <exception type>)`, and the oracle compares those with the
exception type ignored.

Each side is driven through the entry points its own filesystem really
calls, which was a deliberate choice over picking whichever pair looked
symmetric:

* native — `_url()` (that is `_split_url` plus the foreign-federation
  check) then `_strip_protocol()`. That is literally what `info`, `ls`
  and `cat_file` do in `core.py`.
* pelicanfs — `_check_fspath()`, which `_dirlist_dec` and
  `_match_namespace` call for `info`, `exists` and `cat_file`.

Three things are excluded from the predicate, each absorbed by a named
function and pinned by its own test:

1. **Exception type on rejection.** `ValueError` against
   `PelicanException(RuntimeError)`. 31 895 of the mutual rejections in
   a 40 000-example sweep differ only this way; leaving it in would
   drown everything else.
2. **Trailing separators.** fsspec specifies `_strip_protocol` to drop
   them, and it does; `_check_fspath` has no such contract and keeps
   them. `canonical()` drops them on both sides — the same thing
   `normalize()` in `test_differential` already does for entry names.
3. **The `+native` scheme aliases.** The two distributions must not
   claim the same fsspec protocol name (README). A caller writing
   `pelican+native://` means `pelican://`; `for_pelicanfs()` rewrites it
   before pelicanfs sees it.

## Measurements

### Phase 1 sweep

A 150 000-example offline sweep (scratch script, not committed) over the
grammar, comparing the direct front doors with the federation drawn from
the same host list:

```
examples: 150000
  osdf-netloc PurePosixPath normalization   2475
  accept/reject mismatch                       0
  OTHER (unexplained)                          0
```

So the direct door has exactly **one** class of disagreement. That is
why `_explained_by()` has one entry for the "ok/ok" case.

The composed door — `_strip_protocol` then `_check_fspath`, which is what
`glob` does — disagrees with the native side on about **35%** of
examples, in two clusters:

* `('reject', 'ok')` ~12 700/40 000 — an `osdf://` URL loses its
  federation and is silently retargeted at whatever the instance is
  bound to.
* `('ok', 'reject')` ~1 240/40 000 — a `pelican://host:port/...` or
  userinfo URL becomes `host:port/...`, in which urlparse reads `host`
  as a scheme, and `_check_fspath` raises `InvalidDestinationURL`.

Both are facets of one root cause (pelicanfs's two path front doors do
not compose) but they have different user-visible symptoms, so they got
separate register entries.

### The mistake that nearly made the oracle vacuous

The first run of the phase-1 sweep reported **zero** disagreements of any
kind. Two separate reasons, both of them the oracle quietly comparing
nothing:

1. `pelicanfs.PelicanFileSystem.__init__` appends a trailing slash to
   `federation_discovery_url`, and `_validate_discovery_url` compares
   the strings exactly. The fuzzer's stub set `discovery_url` without
   the slash, so *every* URL-spelled federation mismatched and every
   such example was a mutual rejection.
2. The federation host strategy did not include `osg-htc.org`, so every
   `osdf://` spelling named a foreign federation and was rejected on
   both sides before any path semantics were reached.

`test_the_fuzzer_reaches_every_shape` exists because of (2): it asserts
the generator actually emits each form it claims to.
`test_the_pelicanfs_stub_matches_a_real_instance` exists because of the
stub shortcut generally.

### Mutation checks

The oracle was checked against planted bugs rather than trusted:

| Planted bug | Result |
| ----------- | ------ |
| `_strip_protocol` collapses `//` to `/` | caught, shrunk to `'example.org//a'` |
| `_split_url` forgets the federation in a URL | caught, shrunk to `'osdf:///'` |

Both shrank to a one-line, readable bug report, which was the point of
ordering every `sampled_from` list simplest-first.

### Why the stub, and what it costs

`_check_fspath` reads and writes exactly one attribute, so the fuzzer
builds a `PelicanFileSystem` with `__new__` instead of the constructor.
Measured on this machine:

```
real ctor  : 0.271 ms/instance
stub       : 0.00021 ms/instance
```

1300x — the difference between a 2 000-example budget and a 200 000-one,
and the real constructor also opens an aiohttp session per instance.
`test_the_pelicanfs_stub_matches_a_real_instance` guards the shortcut
against `__init__` growing another attribute `_check_fspath` depends on.

### An import-order landmine the fuzzer tripped

Adding a module-level `pytest.importorskip("pelicanfs.core")` to
`test_fuzz_paths.py` made 38 previously passing tests fail with
`CERTIFICATE_VERIFY_FAILED`, in modules that had not changed.

`aiohttp.connector` builds its default verified SSL context **at import
time** (`_SSL_CONTEXT_VERIFIED = _make_ssl_context(True)`), so the trust
store is snapshotted by whoever imports aiohttp first. The harness sets
`SSL_CERT_FILE` in the `_client_trust` fixture, and it cannot set it any
earlier, because the server generates the CA during startup. Before this
change, pelicanfs happened to be imported first from inside that
fixture, so the suite passed by accident of ordering.

`_client_trust` now rebuilds `aiohttp.connector._SSL_CONTEXT_VERIFIED`
after setting the variable, and restores it on teardown. Verified by
running the modules in both orders.

### Phase 2 range sweep

All 169 `(start, end)` pairs from
`[None, -20, -14, -13, -5, -1, 0, 1, 5, 12, 13, 14, 20]` against the
13-byte `hello_world.txt`:

The first classifier said:

```
99 of 169 disagree
  negative offset         71     <- WRONG
  start past EOF          21
  inverted or zero-width   7
  OTHER                    0
```

**That classification was an overfit and had to be thrown away.** It
called every disagreement involving a negative bound a "negative offset"
problem without checking the hypothesis. Probing the individual pairs
showed `cat_file(path, -5, -1)`, `(-13, -1)`, `(0, -1)`, `(None, -1)`
and `(2, -1)` all return the right bytes on pelicanfs. Negatives are not
the problem. Re-classified by resolving each bound against the size
first:

```
99 of 169 disagree
  empty or inverted            41
  start before the beginning   22
  start past EOF               36
  OTHER                         0
```

`start before the beginning` is a start that resolves below zero —
`data[-20:-5]` on 13 bytes, which a slice clamps to `data[0:8]` and
which a caller asking for "the last 20 bytes" of a shorter object
produces. pelicanfs forwards the unclamped offset into a Range header
and the origin answers 416. `start past EOF` was already registered; the
other two are new, and the register entry for the clamping one says
explicitly that in-range negatives work, so the next reader does not
repeat the mistake.

This is the second time in this project that a plausible reading of the
code produced the wrong classification, and the second time that probing
individual cases caught it.

### ls

`ls` was mapped the same way, and two more things fell out:

```
ls('/test-namespace/subdir', detail=False)
  native: ['/test-namespace/subdir/nested.txt']
  pure  : ['/api/v1.0/origin/data/test-namespace/subdir/',
           '/api/v1.0/origin/data/test-namespace/subdir/nested.txt']

ls('/test-namespace/subdir', detail=True)
  native: [{'name': '/test-namespace/subdir/nested.txt', 'size': 7, ...}]
  pure  : ValueError: invalid literal for int() with base 10: ''
```

So pelicanfs names entries by the origin endpoint (the same root cause
as `info-name-is-the-endpoint-path`, but a different method and a
different code path), and its listing includes the collection itself.

The second of those **corrected an existing register entry**:
`ls-crashes-on-a-subcollection` said the crash needs a collection
containing a subdirectory. It does not. `subdir` holds one file and no
subdirectory, and `detail=True` still raises — because the listing
echoes the collection, and *that* entry is a collection with no size.
The summary was corrected in place; the key and its pin were left alone.

## Divergences recorded

Eight new entries in `KNOWN_DIVERGENCES.toml`, and one existing summary
corrected:

| Key | Blame | Pinned by |
| --- | ----- | --------- |
| `osdf-two-slash-form-is-normalized` | pelicanfs | `test_osdf_two_slash_form_is_not_normalized` |
| `strip-protocol-loses-the-osdf-federation` | pelicanfs | `test_strip_protocol_keeps_the_osdf_federation` |
| `strip-protocol-rejects-a-port` | pelicanfs | `test_glob_agrees_on_a_ported_federation` |
| `path-rejection-exception-class` | undecided | `test_path_rejections_share_an_exception_type` |
| `url-with-no-path-is-empty` | pelicanfs | `test_url_with_no_path_denotes_the_root` |
| `range-start-before-the-beginning` | pelicanfs | `test_range_start_before_the_beginning_agrees` |
| `inverted-or-empty-range` | pelicanfs | `test_empty_range_agrees` |
| `exists-raises-on-an-unusable-path` | pelicanfs | `test_exists_does_not_raise` |
| `ls-names-are-endpoint-paths` | pelicanfs | `test_ls_names_are_addressable` |
| `ls-echoes-the-collection-itself` | pelicanfs | `test_ls_does_not_echo_the_collection` |

All pins are deterministic, not generated. A strict `xfail` that depends
on the generator finding the case is a flake waiting to happen, and a
pin is a bug report: it should read as one.

`strip-protocol-rejects-a-port` is pinned end to end, through `glob()`
against the test federation, because that federation runs on an
ephemeral port and so reproduces the bug for free.

## Constraints honoured

* **No `fork()`.** Hypothesis runs in-process; nothing here forks or
  uses `multiprocessing`. The budget is managed by example counts, not
  by parallelism.
* **`skip_instance_cache=True`.** Every fresh pelicanfs goes through the
  `new_pelicanfs` factory, which sets it. `test_info_agrees_on_size` in
  the operation fuzzer needs it per example, since pelicanfs's `info`
  is stateful.
* **CI speed.** See below.

## Timings

| | Before | After |
| - | ------ | ----- |
| Result | 81 passed, 7 xfailed | 92 passed, 17 xfailed |
| Wall clock | ~2.6 s | ~8.3 s |

Measured over four consecutive full runs: 8.75 s, 8.48 s, 8.09 s,
8.29 s, all green. The ~5.7 s added is almost entirely Hypothesis's
per-example overhead on the pure fuzzer, not the functions under test.

The `ci` profile gives the pure fuzzer 1 500 examples and the
federation-backed fuzzer 15 (`max_examples // NETWORK_BUDGET_DIVISOR`,
floor 5). `soak` is 200 000 and 2 000. The soak profile was run end to end once:
`test_denotation_agrees` at 200 000 examples passed in 260.85 s.

Hypothesis picks a fresh seed per run, so the federation-backed tests
draw different examples each time; the four runs above are also a small
flake check.

## Dead ends and things deliberately not done

* **Comparing `_strip_protocol` to `_strip_protocol`.** The obvious
  symmetric pairing, and wrong: pelicanfs's keeps the host and is not a
  namespace path, so the comparison is between two different kinds of
  thing. The composed-door property captures what actually matters.
* **Fuzzing the composed door as a passing property.** It fails on a
  third of examples, so it can only be a pin. The *native* side's
  composability is fuzzed instead, as the control.
* **Fuzzing `ls` on the namespace root.** It crashes pelicanfs
  (`ls-crashes-on-a-subcollection`, already pinned). Generating it again
  would spend network round trips re-finding a known bug.
* **Random text as path segments.** Tried and discarded in favour of an
  explicit atom list. Random text finds encoding bugs; what has actually
  broken pelicanfs is structural, and an explicit list shrinks to
  something a human can read.
