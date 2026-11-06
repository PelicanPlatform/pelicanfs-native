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

---

# Round two: stateful testing, generated names, a corpus

Working notes from the second round (branch `fuzzer-stateful`). The
first round fuzzed the inputs to a single call; this round fuzzes
sequences, fuzzes the names the federation holds, and makes the
findings survive the machine that found them.

## What was built

| File | What it is |
| ---- | ---------- |
| `test/corpus/export.toml` | the object-name corpus: the export is built from it |
| `test/corpus/path_spellings.toml` | the path-spelling corpus: replayed, and seeds the generator |
| `test/fuzz_export.py` | builds the export; the containment rules |
| `test/fuzz_oracle.py` | shared reduction and absorption for the federation-backed fuzzers |
| `test/test_fuzz_names.py` | phase 3, differential fuzzing of object names |
| `test/test_fuzz_stateful.py` | phase 4, the `RuleBasedStateMachine` |

`conftest.py` gained a second namespace, `/fuzz-namespace`, built from
the manifest and separate from the fixed three-object export, so the
fuzzers can create and delete without disturbing the hand-written
tests.

## Three views, and which one is the truth

The oracle is no longer two opinions. The test origin is
`Origin.StorageType: posixv2` over a real directory, so after any
operation the harness can walk `federation.fuzz_export_dir` and see
what the federation actually holds. Every mutation is checked against
it, and the stateful machine's invariant compares model, disk and
libraries after every step.

This is not a tie-break. It says which implementation is *wrong*, and
twice in this round it said the **harness** was wrong, which a
two-sided comparison could not have:

* `listing()` computed its expectation from the model, and a soak
  failed with `native ls() says ['00-a.txt', 'sub'], disk says
  ['00-a.txt']`. Deleting the only object in a collection leaves the
  empty collection behind on the origin, so `ls` was right and the
  model was incomplete. The rule now reads the directory.
* `find_everything()` had the same fault, fixed the same way.

## The cache, decided rather than tolerated

`Cache.EnableV2` means a read after a write can legitimately serve a
stale answer. The decision, in two parts:

**Writes.** Every path the machine writes is written exactly once.
There is then no earlier version of an object for anything to serve,
so no retry loop is needed and none exists. The cost is that
overwrites cannot be explored by the machine, which is fine because
the two implementations disagree about what an overwrite *means* (see
`put-file-overwrites-on-one-side-only`) and a shared model stops being
possible after the first one. That divergence is pinned
deterministically instead.

**Deletes.** A delete necessarily creates a stale answer, so the
once-only rule does not cover it. Two soaks settled what to do:

1. The first asserted both clients report the object gone. It failed
   at run 266: `native.exists()` still True, object gone from disk.
2. The second weakened that to "the two must agree with each other".
   It failed at run 298: native True, pelicanfs False.

The same write/delete/exists sequence on a freshly started federation
is consistent **six times out of six**, so this is staleness that
appears once the federation has been under load — and a differential
assertion cannot settle it, because the two clients do not necessarily
resolve to the same tier for the same object. So the delete is
verified against the export directory, which cannot be stale, and the
clients are not asked. Retrying until they agree was the alternative
and is worse: it turns a client that never notices a delete into a
slow pass.

Both of these only appear in a soak. Short runs route to the origin;
by run 266 the federation has been up long enough for the cache to be
in play. That is worth knowing before reading any short green run as
evidence of much.

## Containment: the dangerous direction is local, not remote

The fuzzer generates hostile object names on purpose. The remote side
is a throwaway federation on loopback; the danger is the *harness*
turning a remote name into a local path. `os.path.join(dest,
"/etc/passwd")` is `"/etc/passwd"` and `Path("/a") / "/etc/passwd"` is
`Path("/etc/passwd")`, so one generated `..` or leading separator in a
recursive `get` destination is enough.

Four controls, in order of precedence:

1. **No local path is ever derived from a generated name.** Local
   files are named by `opaque_local_name()`, a hash. Traversal is not
   filtered, it is unrepresentable. This is the control that matters;
   the rest are belt and braces.
2. **Containment checks** where a real name must reach the filesystem
   — building the export, which has to create the hostile names.
   `contained()` compares `realpath`s with a trailing separator,
   because a bare `startswith` passes `/tmp/foo2` as inside
   `/tmp/foo`, and it is re-checked after creation in case a symlink
   appeared.
3. **Nothing is filtered out of the corpus.** `..`, a leading
   separator and control characters are exactly the inputs worth
   sending remotely. Filtering them would hide the bug class.
4. **A tripwire**: a canary file and a directory snapshot just outside
   the session root, checked at teardown. A control nobody can see
   fail is not a control.

Mutations are additionally guarded: `guard_mutation()` asserts the
path resolves to the test federation before any write or delete.
`osdf://` resolves to the real production OSDF, so this is not
hypothetical. `rm` is restricted to paths the model created.

Runs are made through `scripts/fuzz-in-container.sh`, which mounts the
tree read-only.

## Generated names: what the export now holds

34 names (33 on a case-insensitive volume, where `casename.txt` and
`CaseName.txt` collide; `build_export` detects the collision, keeps
the first, and reports the casualty, and
`test_the_export_is_what_the_manifest_asked_for` asserts the casualty
list is only ever that pair). Sizes 0, 1, 7, 4096 and 65537.

Results, with the export directory as the reference:

| | native | pelicanfs |
| - | ------ | --------- |
| `cat_file` fails | 7 of 34 | 5 of 34 |
| `exists` wrong | 0 | 14 of 34 (says False, then reads them) |
| `exists`/`cat` self-inconsistent | 7 | 2 |

Three entries came out of it, all outside the held `info()`/`ls()`
family: `exists-ignores-encoding`,
`native-rejects-a-literal-percent-in-a-name` and
`native-listing-names-are-percent-encoded`.

A drafting mistake worth recording, because it is the same mistake the
first round made twice. The first version of the exists/read
self-consistency test asserted pelicanfs was clean and the native side
was not. It was run on macOS, where the probe stopped at the first
mismatch, and it was wrong: pelicanfs is inconsistent about
`pct%25.txt` and `pct%20dir/child.txt` too. Both sets are measured now
and the pin asserts only the difference — five names the native side
adds on its own.

Likewise `fuzz_oracle.explains_exists` originally tried to decide from
the spelling which names need percent-encoding. It could not:
`amp&eq=1.txt` and `at@sign.txt` survive while `quote'single.txt` does
not, so the predicate was a list of observations pretending to be a
rule. It keys on the disagreement against ground truth instead — the
object is on disk, one library finds it, the other says it is not
there — which needs no rule and cannot drift.

## Findings held back

**`info()` builds a cache URL with the host spliced into the path.**
The first stateful soak failed on a fresh pelicanfs instance's *first*
call, having requested

```
https://localhost:37951/api/v1.0/cache/data/localhost:37951/fuzz-namespace/run-529/00-a.txt
```

— the cache endpoint with the federation host inside the path, the
same shape as `strip-protocol-rejects-a-port`. Two reasons it is not
in the register. It is `info()`, whose WebDAV layer is being rewritten
upstream and whose findings are on hold. And it does not reproduce
from the shrunk two-step sequence on a fresh federation: a plain
write-then-stat works, with a correct `origin/data/...` URL. It needed
500-odd machine runs of accumulated federation state. Registering it
on a reproduction nobody else can run would be the third time this
project asserted a mechanism from a symptom.

The machine therefore absorbs **any** `FileNotFoundError` from
pelicanfs's `info()` on an object the export directory holds, under
`info-is-stateful`, not just the post-first-call case. The cost is
stated in the code and is real: the machine can no longer find an
`info()` bug at all. That is the price of the hold, and the comment
says to narrow it back when the hold lifts.

**Exception classes on an unreachable object.** Both libraries fail to
read `semi;colon.txt`, `hash#frag.txt`, `question?q.txt` and
`pct%25.txt`; they raise `PelicanFileNotFoundError`,
`FileNotFoundError` and `NoAvailableSource` in various pairings. The
name oracle compares *reachability* and not the exception class, which
is deliberate: holding mutually-unreachable names to a shared class
would turn every shared wart into a finding, and the class question is
already `path-rejection-exception-class`'s. Recorded here rather than
registered.

**pelicanfs silently drops a control character.** `tab\tname.txt`
reaches the origin as `tabname.txt` on the pelicanfs side. Both
libraries fail to read the object, so there is no reachability
divergence to pin; noted because a silently rewritten name is a
different kind of wrong from a refused one.

## The persistent corpus

Hypothesis's example database lives in `.hypothesis/`, is gitignored,
and is a local cache: a find on one laptop is not reproducible on
another and never reaches CI. Two checked-in corpora replace it for
the inputs worth keeping.

* `test/corpus/export.toml` — the export manifest. The federation is
  built from it, so every name in it is exercised by three sweeps on
  every run.
* `test/corpus/path_spellings.toml` — 37 spellings: both shrunk
  counterexamples from the round-one mutation checks, one spelling per
  register entry, and the structural and syntactic shapes. Replayed
  deterministically by `test_corpus_spellings_agree` against two
  federations, and unioned into `spellings()` so the generator starts
  from them. The corpus branch is first in the `one_of` so that
  Hypothesis, which shrinks towards the first branch, reduces to a
  corpus entry where one will do.

`test_the_corpus_is_loaded_and_covers_the_register` and
`test_the_manifest_covers_the_classes_it_claims` exist because a
corpus that silently failed to load would make all of that vacuous —
the same failure mode as round one's `test_the_fuzzer_reaches_every_shape`.

## atheris: checked, and not usable

The three pure path functions are ideal libFuzzer targets, so atheris
was the obvious tool. It does not work here, and this was established
by running it rather than by reading release notes:

* **No wheel.** atheris 3.1.0 publishes exactly three wheels, all
  `manylinux2014_x86_64` (cp312, cp313, cp314). The development host
  is macOS arm64 / cp314 and the container is Linux aarch64 / cp311,
  so pip falls back to the 3.0.0 sdist on both.
* **The sdist does not build**, on either, with:

  ```
  RuntimeError: Failed to find libFuzzer; you may be building using Apple Clang.
  ```

  It needs a clang built with compiler-rt. macOS has only Apple Clang
  and no Homebrew LLVM on this machine; the container has only the
  Debian system clang. Building LLVM from source is not a reasonable
  test dependency.

So: **no coverage-guided fuzzing**, and the fallback is Hypothesis's
`target()`, measured rather than assumed. See the table in
`test_fuzz_paths.py`. Summary: targeting lifts the mutual-acceptance
rate from ~30% to ~33% and the mean path depth from 3.7 to 4.4, which
is worth having in a long hunt — but one run in three spent **sixty
times** the wall clock to get through a tenth of the budget, and in
that run the plain search saw five times as many interesting examples
in a hundredth of the time. It is therefore a soak-profile test and
not a default one. Calling that a success would be rounding up.

## The state machine that explored nothing

The first version passed in 2.3 seconds and was close to vacuous. The
instrumentation added to check said so:

```
these rules never fired: ['classify', 'find_everything', 'read']
fired: {'check': 1, 'check_absent': 24, 'download': 1, 'listing': 4,
        'read_through_open': 1, 'remove': 2, 'stat': 3, 'write': 4}
```

24 of 40 steps went to `check_absent`, the one rule needing no bundle
entry and therefore available at every step, including the early ones
where nothing had been written yet. Two fixes: an `@initialize` that
seeds one object so the bundle rules are reachable from step one, and
folding `check_absent` into `check` as a boolean so it stops competing
for the schedule.

The coverage guarantee then moved to `test_every_rule_runs`, which
calls every rule once in a fixed order. Asserting per-rule coverage
over a random schedule would only have converted the problem into a
flake; the deterministic test gives the guarantee and doubles as a
smoke test, and the Hypothesis run asserts only that it was not
vacuous.

This is the third time in this project that an instrument reported
green while measuring nothing, after round one's zero-disagreement
sweep and its missing `osg-htc.org` host. It will not be the last;
the habit of asserting that the generator reached what it claims to
reach is the only thing that has caught it.

## Divergences recorded this round

| Key | Blame | Pinned by |
| --- | ----- | --------- |
| `exists-ignores-encoding` | pelicanfs | `test_exists_is_true_for_an_object_it_can_read` |
| `native-rejects-a-literal-percent-in-a-name` | pelicanfs-native | `test_native_reads_a_name_holding_a_literal_percent`, `test_neither_side_claims_an_object_it_cannot_read` |
| `native-listing-names-are-percent-encoded` | pelicanfs-native | `test_native_listing_names_are_addressable` |
| `put-file-overwrites-on-one-side-only` | undecided | `test_rewrite_disagrees` |
| `write-surface-is-asymmetric` | undecided | `test_the_write_surfaces_are_disjoint` |

One existing absorption was widened rather than a new entry added:
`_explains_range` now treats `stop <= begin` as empty, because a later
seed drew `cat_file(path, None, 0)`. An explicit `(0, 0)` does agree —
`inverted-or-empty-range` says so and it is still true — but
`(None, 0)` resolves to the same empty range and answers 416 on
pelicanfs, so pelicanfs's behaviour on one range depends on whether
the caller named the start.

## The write surface, measured

Against the same writable origin, same token, same config:

| | native | pelicanfs |
| - | ------ | --------- |
| `put_file` | works | works |
| `put_file` over an existing object | `PelicanFileExistsError` | overwrites |
| `pipe_file` | works | `aiohttp InvalidUrlClientError` |
| `rm_file` | works | `NotImplementedError` |
| `touch` | works | `NotImplementedError` |
| `makedirs` | `NotImplementedError` | returns, creates nothing |

`put_file` being the only mutation both implement is why it is the
state machine's only mutation. The `pipe_file` mechanism is in
pelicanfs's `__init__`: `self._pipe_file = self.http_file_system._pipe_file`
binds HTTPFileSystem's bound method, so `_check_fspath` is never
reached and the namespace path goes to aiohttp as a URL. The
`makedirs` row is why every assertion in that pin is against the
export directory and not against a return value.

## Timings

Measured in the container (`scripts/fuzz-in-container.sh -q`), which
is where every number in this round was taken:

| | Before this round | After |
| - | ----------------- | ----- |
| Result | 97 passed, 21 xfailed | 178 passed, 1 skipped, 23 xfailed |
| Wall clock | 18.9 s | 35.7 s |

Where the time goes, slowest first:

```
8.79s  test_fuzz_paths.py::test_denotation_agrees
6.15s  test_fuzz_paths.py::test_native_strip_protocol_is_idempotent
4.82s  test_fuzz_paths.py::test_native_strip_protocol_returns_a_rooted_path
3.23s  test_fuzz_paths.py::test_native_path_front_doors_compose
2.69s  (federation startup)
1.00s  test_fuzz_stateful.py::test_a_sequence_of_operations_agrees
0.76s  test_fuzz_names.py::test_neither_side_claims_an_object_it_cannot_read
0.55s  test_fuzz_names.py::test_cat_file_agrees_on_every_name
```

Almost none of the increase is the new work: the stateful machine
costs a second and the three name sweeps under two between them. It
is the **pure** path fuzzers, which roughly doubled. Seeding
`spellings()` from the corpus is why — a corpus spelling is far more
likely to be *accepted* than a randomly generated one, and an accepted
spelling does more work on both sides than a rejected one. That is the
intended effect rather than overhead, so it was left alone.

The skipped test is the targeted search, which is soak-only.

Soak, for reference: the stateful machine at `--hypothesis-profile=soak`
is 666 examples of up to 50 steps and takes **8 m 25 s** to pass
clean, which is why it needs its own `pytest.mark.timeout` (above).
Six soaks were run during this round and the first five all found
something: the held `info()` finding, two harness faults where the
model disagreed with the export directory, the delete-staleness
question, and the pytest-timeout misdiagnosis. The sixth is the clean
one. That ratio is the argument for soaking the state machine rather
than reading anything much into the 35-second default run.

## Reading the last exception instead of the first

A later soak died with

```
hypothesis.errors.FlakyStrategyDefinition: Inconsistent data generation!
Data generation behaved differently between test cases.
The second run drew more data than the first run.
```

That reads like a nondeterministic strategy, and the obvious suspects
were `listing` and `find_everything`, which carried
`@precondition(lambda self: self.model)` — a rule whose *availability*
depends on whether an earlier write succeeded, which against a live
federation is external state. The preconditions were removed. **The
next soak failed identically**, which is the useful part.

The actual cause was the *first* exception in the group rather than
the last:

```
Failed: Timeout (>300.0s) from pytest-timeout.   <- inside put_file
hypothesis.errors.FlakyFailure: Inconsistent results from replaying a test case!
  last: INTERESTING from Failed at .../outcomes.py:162
  this: INTERESTING from FlakyStrategyDefinition at .../datatree.py:1108
```

`pyproject.toml` sets `timeout = 300`, which is right for the default
profile and far too short for a soak — 666 sequences of up to 50
network steps is several minutes of legitimate work. pytest-timeout
interrupted Hypothesis mid-draw and Hypothesis reported the only thing
it could see, which was that the draws no longer matched. The fix is
`@pytest.mark.timeout(3600 if SOAK else 120)`.

This is the third time in this project that a plausible reading of a
symptom produced the wrong mechanism, and the first two are recorded
further up this file. The pattern each time: the explanation was
*available* from the evidence and was not read. Here the first
exception in a two-exception group said "Timeout" in plain English.

The precondition removal was kept, because the preconditions were
genuinely state-dependent and the bundle already models availability
correctly — but it fixed nothing, and saying otherwise would be
exactly the mistake this section is about.

## Controls that can be seen failing

`test/test_containment.py` exercises the safety machinery itself, with
no federation and in a tenth of a second:

* `contained()` accepts the root and its children; rejects a sibling
  with a shared prefix (`/tmp/foo2` against `/tmp/foo`, the classic
  way a prefix check is wrong); rejects traversal; and follows
  symlinks out of the root, which is what `realpath` on both sides
  buys.
* `opaque_local_name()` is shown to be untraversable for seven hostile
  spellings, *and* the naive `os.path.join` is asserted to escape for
  the same inputs — so if the demonstration ever stops demonstrating
  anything, the test says so rather than passing quietly.
* `build_export()` drops `../outside.txt` and `sub/../../escape.txt`
  and the files are asserted absent afterwards.
* `tripwire_violations()` is quiet when work stays inside the session
  root and fires on a modified canary, a deleted canary and a vanished
  neighbour. It was extracted from the fixture for exactly this: a
  check nobody has ever watched fail is a comment.
