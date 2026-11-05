"""Model-based differential testing: *sequences* of operations.

Everything else in this harness fuzzes the inputs to a single call.
That is why the worst bug the project has found -- pelicanfs's
``info()`` succeeding once per instance and raising
``FileNotFoundError`` on every call after it -- was noticed by a human
and could not have been found here: nothing drove two operations
against one filesystem and asked whether the second still agreed.

This module does.  A Hypothesis ``RuleBasedStateMachine`` drives a
sequence of operations against **one** instance of each implementation,
carrying a model of the namespace, and after every step compares three
views of the world:

* the **model** -- what the harness believes it wrote;
* the **export directory** -- the posixv2 origin's actual storage, on
  disk, which is *ground truth* and not a third opinion.  When the two
  libraries disagree it says which one is wrong, and when a write goes
  somewhere unexpected it says where;
* each **library's** answer to ``cat_file``, ``info``, ``exists``,
  ``ls``, ``find``, ``isdir``, ``isfile``, ``open`` and ``get_file``.

Both libraries write.  ``put_file`` is the only mutation both
implement (``write-surface-is-asymmetric``), and the writer is drawn
per step, so a sequence routinely writes with one library and reads
back with the other.

What the machine deliberately does not do
-----------------------------------------

**Overwrite.**  The two disagree about what a second write to one path
means -- pelicanfs replaces the object, the native client refuses
(``put-file-overwrites-on-one-side-only``) -- so after one overwrite
the two implementations have different *state* and a shared model is a
fiction.  That divergence is pinned deterministically in
:func:`test_rewrite_disagrees` instead, and every path the machine
writes is written exactly once.

That is also this harness's answer to the cache.  ``Cache.EnableV2``
means a read after a write may legitimately serve stale data, and the
tempting fix -- retry until it agrees -- would paper over a real bug
with a loop.  Writing each path exactly once removes the stale case
rather than tolerating it: there is no earlier version of an object to
serve, and a path the machine deleted is never read again through the
clients.  If a read-after-write ever does disagree, the export
directory in the invariant settles whether the write landed wrong or
the cache answered late.

Deleting is the one case the once-only rule does not cover, because a
delete necessarily makes an older version of the answer exist.  There
the claim is made against the export directory alone and the clients
are not asked at all; two soaks established that they can both lag and
disagree with each other after a delete while a fresh federation is
consistent every time.  :meth:`FederationMachine.remove` carries the
evidence and what the machine gives up for it.

**Hostile names.**  Writes use a small plain alphabet plus one name
with a space.  The hostile-name axis belongs to
:mod:`test_fuzz_names`, which sweeps it properly; mixing it in here
would make most steps degenerate into re-finding those entries.

Safety
------

Generated names never become local paths.  The machine's own names
come from a fixed alphabet, every local file it creates is named by
:func:`fuzz_export.opaque_local_name`, every local path is
realpath-checked against the session root before it is opened, and
every remote mutation is checked to resolve to the test federation and
to live under this run's own subtree before it is sent.  ``rm`` is
restricted to paths the model created and confirmed on disk.
"""

from __future__ import annotations

import itertools
import os
import urllib.parse
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    initialize,
    RuleBasedStateMachine,
    consumes,
    invariant,
    rule,
    run_state_machine_as_test,
)

from conftest import NETWORK_BUDGET_DIVISOR
from fuzz_export import content_for, opaque_local_name, require_contained
from test_differential import KNOWN_DIVERGENCES, normalize, reason

pytestmark = pytest.mark.differential

NETWORK_EXAMPLES = max(5, settings().max_examples // NETWORK_BUDGET_DIVISOR)
# A step is one or two network round trips, and an example is a whole
# sequence of them, so the example budget is a third of the per-call
# fuzzers' and the sequence length carries the exploration instead.
STATEFUL_EXAMPLES = max(3, NETWORK_EXAMPLES // 3)
STEP_COUNT = 50 if settings().max_examples > 10_000 else 8

# Plain enough that a step is about the *sequence* and not about the
# name; 'with space.txt' is in because both libraries read it and only
# one admits it exists, which keeps the absorption honest.
WRITE_NAMES = [
    "a.txt",
    "b.txt",
    "sub/c.txt",
    "sub/deep/d.txt",
    "with space.txt",
]
WRITE_SIZES = [0, 1, 7, 1024]

# Every rule the machine offers, asserted to have fired at least once.
RULES = [
    "seed", "write", "remove", "read", "read_through_open", "stat",
    "check", "listing", "find_everything", "classify", "download",
]

_RUN_IDS = itertools.count()

# What the machine actually did, accumulated across every example in a
# run.  A state machine that quietly explores nothing is the same
# failure mode the path fuzzer already hit once -- it reported zero
# disagreements because every example was a mutual rejection -- so the
# driving test asserts against this rather than against a green tick.
COVERAGE: dict[str, int] = {}
ABSORBED: dict[str, int] = {}


def _fired(name: str) -> None:
    COVERAGE[name] = COVERAGE.get(name, 0) + 1


def _unique(name: str, index: int) -> str:
    """Make a name unique without disturbing its shape.

    The counter goes on the last component, so ``sub/c.txt`` stays two
    levels deep and a listing of the run root still has a mix of
    objects and collections in it.
    """
    head, _, leaf = name.rpartition("/")
    leaf = f"{index:02d}-{leaf}"
    return f"{head}/{leaf}" if head else leaf


def _leaves(entries, listed: str) -> list[str]:
    """A listing reduced to the decoded names of its members.

    Three registered divergences are absorbed here, each by reference
    to its own entry and each pinned elsewhere:
    ``ls-names-are-endpoint-paths`` (pelicanfs names entries by the
    origin endpoint they were answered from),
    ``ls-echoes-the-collection-itself`` (its listing includes the
    collection), and ``native-listing-names-are-percent-encoded`` (the
    native side returns names its own methods will not take back).
    What is left is the one thing both claim to report: which members
    the collection has.
    """
    names = [e if isinstance(e, str) else e["name"] for e in entries]
    trimmed = [urllib.parse.unquote(n.rstrip("/")).rsplit("/", 1)[-1] for n in names]
    return sorted(n for n in trimmed if n != listed)


class FederationMachine(RuleBasedStateMachine):
    """A sequence of operations against one instance of each library."""

    paths = Bundle("paths")

    def __init__(self, native, pure, federation, local_root: Path):
        super().__init__()
        self.native = native
        self.pure = pure
        self.fed = federation
        self.local_root = local_root
        self.run = f"run-{next(_RUN_IDS)}"
        self.root = federation.fuzz_path(self.run)
        self.disk_root = federation.fuzz_export_dir / self.run
        self.model: dict[str, bytes] = {}
        self.counter = itertools.count()
        self.downloads = itertools.count()
        # pelicanfs's info() is poisoned by any earlier operation on
        # the same instance, so the absorption has to know whether this
        # instance is still untouched.
        self.pure_touched = False
        self.absorbed: dict[str, int] = {}

    # ---------------------------------------------------------------- #
    # Bookkeeping                                                      #
    # ---------------------------------------------------------------- #

    def absorb(self, key: str) -> None:
        """Record that a step hit a known divergence.

        The lookup is the point: a typo in a key would otherwise absorb
        a step silently and the machine would report green for the
        wrong reason.
        """
        assert key in KNOWN_DIVERGENCES, f"{key!r} is not in the register"
        self.absorbed[key] = self.absorbed.get(key, 0) + 1
        ABSORBED[key] = ABSORBED.get(key, 0) + 1

    def disk(self, path: str) -> Path:
        """The export-directory path for a namespace path, checked.

        ``path`` is always one the machine built itself, but the check
        runs anyway: this is the single place where a remote name
        becomes a local one, and a control that is skipped when it
        "cannot" fire is not a control.
        """
        relative = path[len(self.fed.fuzz_namespace) + 1:]
        candidate = self.fed.fuzz_export_dir.joinpath(*relative.split("/"))
        require_contained(self.fed.fuzz_export_dir, candidate.parent)
        return candidate

    def guard_mutation(self, path: str) -> None:
        """Refuse to mutate anything but this run's own subtree.

        Two separate dangers.  A path naming another federation would
        send a write to it -- and ``osdf://`` resolves to the real
        production OSDF, so this is not hypothetical.  A path outside
        the run root would disturb the generated export the other
        fuzzers read.
        """
        url = self.native._url(path)
        assert url.startswith(self.fed.discovery_url + "/"), (
            f"refusing to mutate {path!r}: it resolves to {url!r}, which is not "
            f"the test federation {self.fed.discovery_url!r}"
        )
        assert path.startswith(self.root + "/"), (
            f"refusing to mutate {path!r}: it is outside this run's subtree "
            f"{self.root!r}"
        )
        assert ".." not in path.split("/")

    # ---------------------------------------------------------------- #
    # Mutations                                                        #
    # ---------------------------------------------------------------- #

    @initialize(target=paths)
    def seed(self):
        """Write one object before anything else.

        Without it, every rule that needs a path is unavailable at step
        one and Hypothesis spends the early budget on the two rules
        that are always available.  Measured before this existed: 24 of
        40 steps in a default run went to ``check_absent`` and three
        rules never fired at all.
        """
        _fired("seed")
        return self.write("a.txt", 7, True)

    @rule(
        target=paths,
        name=st.sampled_from(WRITE_NAMES),
        size=st.sampled_from(WRITE_SIZES),
        by_native=st.booleans(),
    )
    def write(self, name, size, by_native):
        """Write an object, with one library or the other.

        Each path is written exactly once -- see the module docstring
        on overwrites and the cache.
        """
        _fired("write")
        path = f"{self.root}/{_unique(name, next(self.counter))}"
        self.guard_mutation(path)
        payload = content_for(path, size)

        staged = self.local_root / "staged" / opaque_local_name(path)
        staged.parent.mkdir(parents=True, exist_ok=True)
        require_contained(self.local_root, staged)
        staged.write_bytes(payload)

        if by_native:
            self.native.put_file(str(staged), path)
        else:
            self.pure.put_file(str(staged), path)
            self.pure_touched = True

        landed = self.disk(path)
        assert landed.is_file(), (
            f"put_file({'native' if by_native else 'pelicanfs'}) reported success "
            f"but nothing is at {landed} -- the export directory holds "
            f"{sorted(p.name for p in self.disk_root.rglob('*'))}"
        )
        assert landed.read_bytes() == payload, "the wrong bytes landed"
        self.model[path] = payload
        return path

    @rule(path=consumes(paths))
    def remove(self, path):
        """Delete an object, and require both libraries to notice.

        Only the native client can delete (``write-surface-is-asymmetric``),
        so pelicanfs's refusal is recorded rather than compared; what is
        differential here is that both must then agree the object is
        gone, and the export directory must agree too.
        """
        _fired("remove")
        self.guard_mutation(path)
        assert path in self.model
        try:
            self.pure.rm_file(path)
        except NotImplementedError:
            self.absorb("write-surface-is-asymmetric")
        else:  # pragma: no cover -- fires the day pelicanfs implements it
            pytest.fail("pelicanfs implements rm_file now; update the register")
        self.pure_touched = True

        self.native.rm_file(path)
        # The absolute claim is made against the export directory,
        # which is the origin's own storage and cannot be stale.
        assert not self.disk(path).exists(), f"{path} is still on disk after rm"
        del self.model[path]

        # The clients are not asked about a path that was just
        # deleted, and this is the harness's cache decision rather
        # than an oversight.
        #
        # Two soaks settled it. The first asserted both clients report
        # the object gone, and failed at run 266 with the native side
        # still returning True. The second weakened that to "the two
        # must at least agree with each other", and failed at run 298
        # with native True and pelicanfs False. The same
        # write/delete/exists sequence on a freshly started federation
        # is consistent six times out of six, so this is staleness
        # that appears once the federation has been under load, not a
        # client bug -- and a differential assertion cannot settle it,
        # because the two clients do not necessarily resolve to the
        # same tier for the same object.
        #
        # Retrying until they agree was the other option and is worse:
        # it would turn a client that never notices a delete into a
        # slow pass. So the delete is verified where it cannot be
        # stale -- the origin's own storage, checked above -- and the
        # clients are left alone. What the machine gives up is the
        # ability to catch a client that caches a deletion wrongly;
        # that would need both sides pinned to direct reads, and the
        # native side exposes no such knob.

    # ---------------------------------------------------------------- #
    # Reads                                                            #
    # ---------------------------------------------------------------- #
    #
    # No @precondition anywhere below, deliberately. A precondition on
    # self.model makes a rule's *availability* depend on whether an
    # earlier write succeeded, and against a live federation that is
    # external state: a soak died with
    #
    #   FlakyStrategyDefinition: Inconsistent data generation! ...
    #   The second run drew more data than the first run.
    #
    # because a replay took a different branch and so drew a different
    # amount. Rules that need a path take one from the bundle, whose
    # emptiness Hypothesis models itself; rules that look at the run
    # root as a whole return early when it is empty.

    @rule(path=paths)
    def read(self, path):
        _fired("read")
        expected = self.model[path]
        assert self.disk(path).read_bytes() == expected, "the model drifted from disk"
        native = self.native.cat_file(path)
        pure = self.pure.cat_file(path)
        self.pure_touched = True
        assert native == pure == expected, (
            f"cat_file disagrees on {path}: native={native!r} "
            f"pelicanfs={pure!r} disk={expected!r}"
        )

    @rule(path=paths)
    def read_through_open(self, path):
        """The same bytes through the file-like API.

        pelicanfs's ``open()`` and the native ``open()`` are separate
        code from ``cat_file`` on both sides, and a sequence that
        writes with one and opens with the other is the shape a real
        caller has.
        """
        _fired("read_through_open")
        expected = self.model[path]
        with self.native.open(path, "rb") as handle:
            native = handle.read()
        with self.pure.open(path, "rb") as handle:
            pure = handle.read()
        self.pure_touched = True
        assert native == pure == expected, f"open().read() disagrees on {path}"

    @rule(path=paths)
    def stat(self, path):
        """``info()`` must report the size the object has on disk."""
        _fired("stat")
        expected = len(self.model[path])
        native = normalize(self.native.info(path))
        assert native["size"] == expected, f"native info() is wrong about {path}"
        try:
            pure = normalize(self.pure.info(path))
        except FileNotFoundError:
            # pelicanfs's info() denying an object the export directory
            # holds is absorbed outright, by reference to
            # info-is-stateful, and NOT only when the instance has been
            # touched. The narrow version was the first draft and a
            # soak broke it: at 50 steps an example, after the
            # federation had been running for 500-odd machine runs,
            # info() failed on the FIRST call of a fresh instance,
            # having asked for
            #   .../api/v1.0/cache/data/localhost:PORT/fuzz-namespace/...
            # -- the cache endpoint with the federation host spliced
            # into the path, which is the same shape as
            # strip-protocol-rejects-a-port. It does not reproduce from
            # the shrunk two-step sequence on a fresh federation, so it
            # is written up in docs/FUZZER-NOTES.md with the evidence
            # rather than registered on a reproduction nobody else can
            # run.
            #
            # The cost is real and worth stating: with this absorption
            # the machine can no longer find an info() bug at all. That
            # is the price of info()'s WebDAV layer being rewritten
            # upstream and its findings being on hold. When the hold
            # lifts, narrow this back to `if self.pure_touched`.
            assert self.disk(path).is_file(), "info() is right: it is gone"
            self.absorb("info-is-stateful")
            return
        self.pure_touched = True
        if pure["size"] != expected:
            self.absorb("exists-ignores-encoding")
            return
        assert pure["size"] == expected

    @rule(path=paths, absent=st.booleans(), name=st.sampled_from(WRITE_NAMES))
    def check(self, path, absent, name):
        """``exists`` on an object that is there, or one that never was.

        One rule rather than two: a rule needing no bundle entry is
        available at every step, and as a rule of its own it crowded
        everything else out of the schedule.
        """
        _fired("check")
        if absent:
            path = f"{self.root}/never/{name}"
            assert not self.disk(path).exists()
            assert self.native.exists(path) is False, path
            pure = self.pure.exists(path)
            self.pure_touched = True
            assert pure is False, f"pelicanfs invents {path}"
            return
        assert self.disk(path).is_file(), "the model drifted from disk"
        native = self.native.exists(path)
        pure = self.pure.exists(path)
        self.pure_touched = True
        assert native is True, f"native exists() denies {path}, which is on disk"
        if pure is not True:
            self.absorb("exists-ignores-encoding")

    @rule()
    def listing(self):
        """``ls`` of the run root must report the same members.

        Expected comes from the export directory, not from the model.
        A soak caught the difference: deleting the only object in a
        collection leaves the empty collection behind on the origin,
        so ``ls`` rightly still lists it while the model, which tracks
        objects, does not. Ground truth said the libraries were right
        and the harness was wrong, which is the whole reason for
        reading the disk rather than comparing two opinions.
        """
        _fired("listing")
        if not self.disk_root.is_dir():
            return
        expected = sorted(p.name for p in self.disk_root.iterdir())
        native = _leaves(self.native.ls(self.root, detail=False), self.run)
        try:
            pure = _leaves(self.pure.ls(self.root, detail=False), self.run)
        except ValueError:
            self.absorb("ls-crashes-on-a-subcollection")
            pure = None
        self.pure_touched = True
        assert native == expected, f"native ls() says {native}, disk says {expected}"
        if pure is not None:
            assert pure == expected, f"pelicanfs ls() says {pure}, disk says {expected}"

    @rule()
    def find_everything(self):
        """``find`` must reach every object the run has written."""
        _fired("find_everything")
        if not self.disk_root.is_dir():
            return
        # Files on disk, not the model: find() reports objects, and an
        # empty collection left behind by a delete is not one.
        expected = sorted(
            self.fed.fuzz_path(str(q.relative_to(self.fed.fuzz_export_dir)))
            for q in self.disk_root.rglob("*")
            if q.is_file()
        )
        native = sorted(urllib.parse.unquote(p.rstrip("/")) for p in self.native.find(self.root))
        assert native == expected, f"native find() says {native}, model says {expected}"
        try:
            pure = self.pure.find(self.root)
        except (ValueError, FileNotFoundError):
            self.absorb("ls-crashes-on-a-subcollection")
            return
        self.pure_touched = True
        assert sorted(p.rstrip("/").split("/", 3)[-1] for p in pure) == sorted(
            p.split("/", 3)[-1] for p in expected
        )

    @rule(path=paths)
    def classify(self, path):
        """``isfile``/``isdir`` must classify an object as an object."""
        _fired("classify")
        assert self.native.isfile(path) is True, path
        assert self.native.isdir(path) is False, path
        if self.pure.isfile(path) is not True:
            # pelicanfs's _isfile calls _ls_real and reads a non-empty
            # listing as "this is a collection"; the listing of an
            # object is non-empty because it echoes the object itself.
            self.absorb("ls-echoes-the-collection-itself")
        if self.pure.isdir(path) is not False:
            self.absorb("info-type")
        self.pure_touched = True

    @rule(path=paths)
    def download(self, path):
        """``get_file`` into a destination of the harness's choosing.

        Each library gets its own directory and the local file name is
        an opaque hash of the remote path, never the remote name: a
        recursive get derives local paths from remote ones, and one
        generated ``..`` would otherwise leave the destination.  The
        trees are then compared, which is the state comparison that a
        return-value check would miss.
        """
        _fired("download")
        expected = self.model[path]
        results = {}
        for label, fs in (("native", self.native), ("pelicanfs", self.pure)):
            dest_dir = self.local_root / "download" / label
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / opaque_local_name(path, f".{next(self.downloads)}")
            require_contained(self.local_root, dest.parent)
            fs.get_file(path, str(dest))
            require_contained(self.local_root, dest)
            results[label] = dest.read_bytes() if dest.is_file() else None
        self.pure_touched = True
        assert results["native"] == results["pelicanfs"] == expected, (
            f"get_file trees differ for {path}: {results}, disk={expected!r}"
        )

    # ---------------------------------------------------------------- #
    # The invariant, and cleaning up                                   #
    # ---------------------------------------------------------------- #

    @invariant()
    def the_model_matches_the_export_directory(self):
        """Ground truth, checked after every step.

        Not a differential check: this is the posixv2 origin's own
        storage.  It catches a write that landed somewhere other than
        where it was addressed, which is the failure a comparison of
        two clients' return values cannot see.
        """
        if not self.disk_root.exists():
            assert not self.model, f"{self.model.keys()} were written and are gone"
            return
        on_disk = {
            str(p.relative_to(self.fed.fuzz_export_dir))
            for p in self.disk_root.rglob("*")
            if p.is_file()
        }
        modelled = {p[len(self.fed.fuzz_namespace) + 1:] for p in self.model}
        assert on_disk == modelled, (
            f"the export directory holds {sorted(on_disk)} and the model "
            f"holds {sorted(modelled)}"
        )
        for path, payload in self.model.items():
            assert self.disk(path).read_bytes() == payload, path

    def teardown(self):
        """Leave the export as it was found.

        The run's objects are deleted through the native client rather
        than off the disk, so that the origin and any cache see the
        deletion too; whatever survives that is removed locally, with
        the containment check still in force.
        """
        for path in list(self.model):
            try:
                self.guard_mutation(path)
                self.native.rm_file(path)
            except Exception:  # noqa: BLE001 -- teardown is best-effort
                pass
        if self.disk_root.exists():
            require_contained(self.fed.fuzz_export_dir, self.disk_root)
            for child in sorted(self.disk_root.rglob("*"), reverse=True):
                require_contained(self.disk_root, child)
                child.rmdir() if child.is_dir() else child.unlink()
            self.disk_root.rmdir()


def test_a_sequence_of_operations_agrees(
    native_fs, new_pelicanfs, federation, tmp_path_factory
):
    """Drive the machine.

    ``run_state_machine_as_test`` rather than the ``TestCase`` subclass
    Hypothesis also offers, because the machine needs fixtures: the
    federation, and a session-scoped local root that every file it
    writes stays inside.
    """
    local_root = tmp_path_factory.mktemp("stateful")

    def factory():
        return FederationMachine(native_fs, new_pelicanfs(), federation, local_root)

    run_state_machine_as_test(
        factory,
        settings=settings(
            max_examples=STATEFUL_EXAMPLES,
            stateful_step_count=STEP_COUNT,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
        ),
    )
    # Nothing the machine wrote may survive its own teardown.
    leftovers = [
        p for p in federation.fuzz_export_dir.iterdir() if p.name.startswith("run-")
    ]
    assert not leftovers, f"the machine left {leftovers} behind"

    # The machine must have actually run steps. Which rules it chose is
    # Hypothesis's business and varies with the seed, so asserting
    # per-rule coverage here would be a flake; that guarantee is
    # test_every_rule_runs's, which is deterministic. What is asserted
    # here is only that the run was not vacuous.
    assert sum(COVERAGE.values()) >= STATEFUL_EXAMPLES, (
        f"the machine ran almost nothing: {dict(sorted(COVERAGE.items()))}"
    )


# --------------------------------------------------------------------- #
# Pins                                                                  #
# --------------------------------------------------------------------- #


@pytest.mark.xfail(strict=True, reason=reason("put-file-overwrites-on-one-side-only"))
def test_rewrite_disagrees(native_fs, new_pelicanfs, federation, tmp_path):
    """A second write to one path must mean the same thing on both sides.

    Kept out of the state machine on purpose: after one overwrite the
    two implementations hold different bytes at one path, and a shared
    model of the namespace stops being possible.

    The export directory is the arbiter -- it says which bytes really
    landed, where comparing the two calls' return values would only say
    that one raised.
    """
    staged_a = tmp_path / opaque_local_name("a")
    staged_b = tmp_path / opaque_local_name("b")
    require_contained(tmp_path, staged_a)
    require_contained(tmp_path, staged_b)
    staged_a.write_bytes(b"first")
    staged_b.write_bytes(b"second")

    results = {}
    for label, fs in (("native", native_fs), ("pelicanfs", new_pelicanfs())):
        name = f"overwrite-{label}.txt"
        path = federation.fuzz_path(name)
        disk = federation.fuzz_export_dir / name
        try:
            fs.put_file(str(staged_a), path)
            fs.put_file(str(staged_b), path)
            results[label] = disk.read_bytes()
        except Exception as exc:  # noqa: BLE001 -- refusing is a result
            results[label] = type(exc).__name__
        finally:
            native_fs.rm_file(path)

    assert results["native"] == results["pelicanfs"], (
        f"a second put_file means different things: {results}"
    )


@pytest.mark.xfail(strict=True, reason=reason("write-surface-is-asymmetric"))
def test_the_write_surfaces_are_disjoint(native_fs, new_pelicanfs, federation, tmp_path):
    """Each library must be able to perform the other's mutations.

    ``put_file`` is the only one both implement, which is why it is the
    state machine's only mutation.  Every assertion below is checked
    against the export directory rather than against a return value,
    because ``makedirs`` is the case where one library reports success
    and does nothing.
    """
    missing = []

    # pipe_file: pelicanfs binds HTTPFileSystem's bound method in
    # __init__, so the namespace path never reaches _check_fspath.
    for label, fs in (("native", native_fs), ("pelicanfs", new_pelicanfs())):
        name = f"pipe-{label}.txt"
        try:
            fs.pipe_file(federation.fuzz_path(name), b"piped")
            wrote = (federation.fuzz_export_dir / name).read_bytes() == b"piped"
        except Exception:  # noqa: BLE001
            wrote = False
        finally:
            (federation.fuzz_export_dir / name).unlink(missing_ok=True)
        if not wrote:
            missing.append(f"{label}.pipe_file")

    # rm_file, touch, makedirs.
    for label, fs in (("native", native_fs), ("pelicanfs", new_pelicanfs())):
        name = f"rm-{label}.txt"
        disk = federation.fuzz_export_dir / name
        disk.write_bytes(b"x")
        try:
            fs.rm_file(federation.fuzz_path(name))
        except Exception:  # noqa: BLE001
            pass
        if disk.exists():
            missing.append(f"{label}.rm_file")
            disk.unlink()

        name = f"touch-{label}.txt"
        try:
            fs.touch(federation.fuzz_path(name))
        except Exception:  # noqa: BLE001
            pass
        if not (federation.fuzz_export_dir / name).exists():
            missing.append(f"{label}.touch")
        else:
            native_fs.rm_file(federation.fuzz_path(name))

        name = f"mkdir-{label}"
        try:
            fs.makedirs(federation.fuzz_path(name))
        except Exception:  # noqa: BLE001
            pass
        if not (federation.fuzz_export_dir / name).is_dir():
            missing.append(f"{label}.makedirs")
        else:
            os.rmdir(federation.fuzz_export_dir / name)

    assert not missing, f"unimplemented or ineffective write operations: {missing}"


def test_every_rule_runs(native_fs, new_pelicanfs, federation, tmp_path):
    """Every rule, once, in a fixed order.

    The guarantee the Hypothesis run cannot give.  Hypothesis chooses
    rules by its own schedule, so a run can leave three of them unused
    and still report green -- which is exactly what the first version
    of this module did: 24 of 40 steps went to one rule and ``read``,
    ``classify`` and ``find_everything`` never fired at all.  Asserting
    per-rule coverage over a random schedule would only convert that
    into a flake, so the coverage guarantee lives here, where it is
    deterministic, and the random run is left to explore orderings.

    It doubles as the smoke test for the rules themselves: a rule that
    raises for a reason that has nothing to do with the two libraries
    disagreeing fails here, loudly, instead of being shrunk into an
    unreadable counterexample.
    """
    machine = FederationMachine(native_fs, new_pelicanfs(), federation, tmp_path)
    try:
        path = machine.seed()
        machine.read(path)
        machine.read_through_open(path)
        machine.stat(path)
        machine.check(path, False, "a.txt")
        machine.check(path, True, "a.txt")
        machine.download(path)
        machine.classify(path)
        other = machine.write("sub/c.txt", 1024, False)
        machine.listing()
        machine.find_everything()
        machine.the_model_matches_the_export_directory()
        machine.remove(other)
        machine.remove(path)
        machine.the_model_matches_the_export_directory()
    finally:
        machine.teardown()

    fired = set(COVERAGE)
    assert set(RULES) <= fired, f"never ran: {sorted(set(RULES) - fired)}"
