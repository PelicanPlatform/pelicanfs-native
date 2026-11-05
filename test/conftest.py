"""A real Pelican federation, launched from the ``pelican-server`` binary.

Both implementations under test are full Pelican clients: the Go client
does its own director interaction, cache selection and token discovery.
Mocking HTTP would mean mocking the federation protocol twice, once per
client, and the mock would become the thing under test.  Launching the
actual server is cheaper to get right and gives the differential harness
a single shared source of truth.

The federation runs entirely on the pure-Go serving paths -- a
``posixv2`` origin and the V2 cache -- so no XRootD installation is
needed and it runs on stock CI runners.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, settings as hypothesis_settings

from fuzz_export import build_export, load_manifest, tripwire_violations

NAMESPACE = "/test-namespace"
# A second namespace, backed by the generated export, so that the
# fuzzers can create and delete objects without disturbing the fixed
# three-object export the hand-written tests assert against.  Every
# mutation in the suite happens under here.
FUZZ_NAMESPACE = "/fuzz-namespace"
STARTUP_TIMEOUT_S = 120.0

# --------------------------------------------------------------------- #
# Hypothesis profiles                                                   #
# --------------------------------------------------------------------- #
#
# Registered at import time, before the Hypothesis pytest plugin's
# pytest_configure runs, so that --hypothesis-profile=soak still wins.
#
# max_examples is the budget for the *pure* path fuzzer, where an
# example costs microseconds. The federation-backed fuzzer runs real
# network round trips at roughly a hundred times the cost, and scales
# itself down by NETWORK_BUDGET_DIVISOR so that one knob moves both.
NETWORK_BUDGET_DIVISOR = 100

# deadline=None throughout: these tests share a process with a Go
# runtime and, in phase two, with a federation, so a per-example time
# limit measures the machine rather than the code. A deadline flake is
# noise that trains people to rerun.
hypothesis_settings.register_profile(
    "ci",
    max_examples=1500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    print_blob=True,
)
hypothesis_settings.register_profile(
    "soak",
    max_examples=200_000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    print_blob=True,
)
hypothesis_settings.load_profile("ci")


@dataclass(frozen=True)
class Federation:
    """Everything a client needs to reach the test federation."""

    discovery_url: str
    ca_file: str
    token: str
    token_file: str
    export_dir: Path
    namespace: str
    log_file: Path
    # The generated export: a second namespace built from
    # test/corpus/export.toml, which is where every mutation goes.
    fuzz_export_dir: Path
    fuzz_namespace: str
    objects: tuple[Any, ...]
    dropped_objects: tuple[str, ...]

    def path(self, *parts: str) -> str:
        """A namespace path inside the fixed test export."""
        return "/".join([self.namespace.rstrip("/"), *(p.strip("/") for p in parts)])

    def url(self, *parts: str) -> str:
        return self.discovery_url + self.path(*parts)

    def fuzz_path(self, *parts: str) -> str:
        """A namespace path inside the generated export.

        Joined with a plain separator and never with ``os.path.join``:
        the parts here are generated object names, and join() treats a
        leading separator as "start over from the root".
        """
        return "/".join([self.fuzz_namespace.rstrip("/"), *(p.lstrip("/") for p in parts)])

    @property
    def host(self) -> str:
        return self.discovery_url.removeprefix("pelican://")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _find_binary(name: str, env_var: str) -> str:
    """Locate a Pelican binary, preferring an explicit override.

    CI sets these after unpacking a release; a developer usually just
    has the binaries on PATH.  The variables deliberately avoid the
    ``PELICAN_`` prefix: viper maps that namespace onto configuration
    keys, so ``PELICAN_SERVER_BINARY`` would be read as the config
    setting ``Server.Binary`` and rejected as unknown.
    """
    override = os.environ.get(env_var)
    if override:
        if not os.path.isfile(override) or not os.access(override, os.X_OK):
            raise pytest.UsageError(f"{env_var}={override!r} is not an executable file")
        return override
    found = shutil.which(name)
    if found:
        return found
    raise pytest.UsageError(
        f"could not find {name!r} on PATH. Install a Pelican release "
        f"(scripts/fetch-pelican.sh downloads one) or set {env_var} to its path."
    )


def _config(root: Path, export_dir: Path, fuzz_export_dir: Path, ports: dict[str, int]) -> str:
    return textwrap.dedent(f"""\
        # Generated by pelicanfs-native's test harness.
        ConfigBase: {root}/config
        Logging:
          Level: "Error"
        Server:
          Hostname: "localhost"
          WebPort: {ports["web"]}
          EnableUI: false
          TLSCACertificateFile: {root}/config/ca.pem
          DbLocation: {root}/server.sqlite
        Origin:
          StorageType: "posixv2"
          Port: {ports["origin"]}
          RunLocation: {root}/origin-run
          Exports:
            - StoragePrefix: {export_dir}
              FederationPrefix: {NAMESPACE}
              Capabilities: ["Reads", "Writes", "DirectReads", "Listings"]
            - StoragePrefix: {fuzz_export_dir}
              FederationPrefix: {FUZZ_NAMESPACE}
              Capabilities: ["Reads", "Writes", "DirectReads", "Listings"]
        Cache:
          EnableV2: true
          Port: {ports["cache"]}
          RunLocation: {root}/cache-run
          StorageLocation: {root}/cache-data
        Registry:
          DbLocation: {root}/registry.sqlite
        Xrootd:
          # The graceful drain before shutdown, 1m by default. Nothing is
          # draining in a test federation, and waiting it out at session
          # teardown dominated the suite's runtime.
          ShutdownTimeout: "0s"
        """)


def _wait_ready(discovery_url: str, ca_file: str, proc: subprocess.Popen, log: Path) -> None:
    """Poll federation discovery until the servers answer.

    The CA is generated by the server during startup, so the trust store
    cannot be built before launching it; the context is created inside
    the loop, once the file appears.
    """
    url = discovery_url + "/.well-known/pelican-configuration"
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    last = "no attempt completed"
    context: ssl.SSLContext | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"pelican-server exited with code {proc.returncode} during startup\n"
                f"{_tail(log)}"
            )
        if context is None:
            if not os.path.exists(ca_file):
                last = f"waiting for the generated CA at {ca_file}"
                time.sleep(0.25)
                continue
            try:
                context = ssl.create_default_context(cafile=ca_file)
            except (OSError, ssl.SSLError) as exc:
                # The file exists but is still being written out.
                last = f"CA not yet loadable: {exc}"
                time.sleep(0.25)
                continue
        try:
            with urllib.request.urlopen(url, timeout=5, context=context) as resp:
                if resp.status == 200:
                    return
                last = f"HTTP {resp.status}"
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(0.25)
    raise RuntimeError(
        f"federation did not become ready within {STARTUP_TIMEOUT_S}s "
        f"(last attempt: {last})\n{_tail(log)}"
    )


def _wait_namespace(discovery_url: str, ca_file: str, namespace: str,
                    proc: subprocess.Popen, log: Path,
                    probe: str = "hello_world.txt") -> None:
    """Wait until the director will route the test namespace.

    For a few minutes after it starts, the director answers 429 with
    "director just restarted" for any prefix it has not yet learned
    about.  The client retries with a growing backoff, so without this
    the cost lands on whichever test happens to run first.
    """
    context = ssl.create_default_context(cafile=ca_file)
    url = (
        f"{discovery_url}/api/v1.0/director/object{namespace}/"
        + urllib.parse.quote(probe, safe="/")
    )

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    last = "no attempt completed"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"pelican-server exited with code {proc.returncode} while the "
                f"namespace was being advertised\n{_tail(log)}"
            )
        try:
            with opener.open(url, timeout=5) as resp:
                last = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            # A redirect to an origin or cache is the success case: the
            # director knows where the namespace lives.
            if exc.code in (301, 302, 303, 307, 308):
                return
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(0.5)
    raise RuntimeError(
        f"the director did not advertise {namespace} within "
        f"{STARTUP_TIMEOUT_S}s (last attempt: {last})\n{_tail(log)}"
    )


def _tail(log: Path, lines: int = 60) -> str:
    try:
        content = log.read_text(errors="replace").splitlines()
    except OSError:
        return f"(no server log at {log})"
    return "--- pelican-server log (tail) ---\n" + "\n".join(content[-lines:])


def _mint_token(binary: str, config_file: Path, url: str, env: dict[str, str]) -> str:
    """Create a read+write token signed by the federation's issuer key.

    The issuer key lives under ``${ConfigBase}/issuer-keys``, which the
    client resolves from the same config file the server was started
    with, so no key material has to be moved around.
    """
    result = subprocess.run(
        [
            binary, "token", "create",
            "--config", str(config_file),
            "--raw-scope", "storage.read:/ storage.create:/ storage.modify:/",
            "--lifetime", "3600",
            url,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"`pelican token create` failed ({result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    token = result.stdout.strip().splitlines()[-1].strip()
    if not token.count(".") == 2:
        raise RuntimeError(f"`pelican token create` did not print a JWT: {result.stdout!r}")
    return token


@pytest.fixture(scope="session")
def federation(tmp_path_factory: pytest.TempPathFactory) -> Federation:
    """Launch a federation-in-a-box for the whole test session."""
    server_bin = _find_binary("pelican-server", "PELICANFS_NATIVE_SERVER_BINARY")
    client_bin = _find_binary("pelican", "PELICANFS_NATIVE_CLIENT_BINARY")

    root = tmp_path_factory.mktemp("fed")
    export_dir = root / "export"
    export_dir.mkdir()
    (export_dir / "hello_world.txt").write_bytes(b"Hello, World!")
    (export_dir / "empty.txt").write_bytes(b"")
    (export_dir / "binary.bin").write_bytes(bytes(range(256)) * 64)
    subdir = export_dir / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_bytes(b"nested\n")

    # The generated export, in its own namespace. Built before the
    # server starts so the origin advertises it from the first scan.
    fuzz_export_dir = root / "fuzz-export"
    objects, dropped = build_export(fuzz_export_dir, load_manifest())

    ports = {"web": _free_port(), "origin": _free_port(), "cache": _free_port()}
    config_file = root / "pelican.yaml"
    config_file.write_text(_config(root, export_dir, fuzz_export_dir, ports))
    (root / "config").mkdir()

    discovery_url = f"https://localhost:{ports['web']}"
    ca_file = str(root / "config" / "ca.pem")
    log_file = root / "pelican-server.log"

    env = dict(os.environ)
    # Test federations live on loopback, which Pelican's SSRF-resistant
    # transport refuses by default; server-initiated transfers need the
    # default blocks lifted.
    env["PELICAN_SERVER_SSRFPROTECTION_SKIPDEFAULTBLOCKS"] = "true"

    with log_file.open("wb") as log:
        proc = subprocess.Popen(
            [
                server_bin, "serve",
                "--module", "director,registry,origin,cache",
                "--config", str(config_file),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
        )

    try:
        _wait_ready(discovery_url, ca_file, proc, log_file)
        _wait_namespace(discovery_url, ca_file, NAMESPACE, proc, log_file)
        _wait_namespace(
            discovery_url, ca_file, FUZZ_NAMESPACE, proc, log_file,
            probe=objects[0].name if objects else "plain.txt",
        )

        client_env = dict(env)
        client_env["PELICAN_SERVER_TLSCACERTIFICATEFILE"] = ca_file
        client_env["PELICAN_FEDERATION_DISCOVERYURL"] = discovery_url
        token = _mint_token(
            client_bin,
            config_file,
            f"pelican://localhost:{ports['web']}{NAMESPACE}",
            client_env,
        )
        token_file = root / "token"
        token_file.write_text(token)
        token_file.chmod(0o600)

        yield Federation(
            discovery_url=f"pelican://localhost:{ports['web']}",
            ca_file=ca_file,
            token=token,
            token_file=str(token_file),
            export_dir=export_dir,
            namespace=NAMESPACE,
            log_file=log_file,
            fuzz_export_dir=fuzz_export_dir,
            fuzz_namespace=FUZZ_NAMESPACE,
            objects=tuple(objects),
            dropped_objects=tuple(dropped),
        )
    except Exception:
        sys.stderr.write(_tail(log_file) + "\n")
        raise
    finally:
        # Escalate quickly: a test federation has nothing worth draining,
        # and a server that has not gone down in a few seconds is not
        # about to.
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=30)


@pytest.fixture(scope="session")
def _client_trust(federation: Federation):
    """Teach the Python client to trust the federation's generated CA.

    Only the Python side is served by environment variables.  The Go
    runtime snapshots the process environment when it initializes --
    which for a c-shared library is at ``dlopen`` time, i.e. when
    ``pelicanfs_native`` is first imported -- so a ``PELICAN_*``
    variable set afterwards is invisible to it no matter how early the
    fixture runs.  The native client is configured through
    ``client_config`` instead (see the ``native_fs`` fixture), which
    reaches ``pelican_config_set`` before initialization.

    TLS verification stays on for both implementations; disabling it
    would hide exactly the class of bug this suite exists to find.

    Depended on by the filesystem fixtures rather than autouse, so tests
    that need no federation (path handling, for one) do not pay to start
    one.
    """
    previous = {
        key: os.environ.get(key)
        for key in ("SSL_CERT_FILE", "BEARER_TOKEN_FILE")
    }
    os.environ["SSL_CERT_FILE"] = federation.ca_file
    os.environ["BEARER_TOKEN_FILE"] = federation.token_file

    # aiohttp builds its default verified context once, at import time
    # of aiohttp.connector, so a module that imported it before this
    # fixture ran has already snapshotted a trust store without the
    # federation's generated CA -- and the CA cannot exist any earlier,
    # since the server generates it during startup. Rebuilding it here
    # is what keeps the suite's result from depending on which test
    # module happened to import pelicanfs first; adding a module-level
    # `import pelicanfs.core` to one test file was enough to make 38
    # tests fail with CERTIFICATE_VERIFY_FAILED.
    connector = sys.modules.get("aiohttp.connector")
    cached_context = getattr(connector, "_SSL_CONTEXT_VERIFIED", None)
    if cached_context is not None:
        connector._SSL_CONTEXT_VERIFIED = ssl.create_default_context()
    try:
        yield
    finally:
        if cached_context is not None:
            connector._SSL_CONTEXT_VERIFIED = cached_context
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(scope="session")
def native_fs(federation: Federation, _client_trust):
    from pelicanfs_native import PelicanNativeFileSystem

    return PelicanNativeFileSystem(
        federation_discovery_url=federation.discovery_url,
        token=federation.token,
        # Configuration, not environment: see _client_trust.
        client_config={"Server.TLSCACertificateFile": federation.ca_file},
    )


@pytest.fixture(scope="session")
def new_pelicanfs(federation: Federation, _client_trust):
    """Build a fresh pure-Python filesystem.

    A factory rather than a single instance, because pelicanfs carries
    per-instance state that the first call mutates (see
    ``test_pelicanfs_info_is_stateful``). A test that means to compare
    one operation should not inherit another test's state.
    """
    pelicanfs = pytest.importorskip(
        "pelicanfs", reason="install the 'differential' dependency group"
    )

    def factory():
        return pelicanfs.PelicanFileSystem(
            federation_discovery_url=federation.discovery_url,
            headers={"Authorization": f"Bearer {federation.token}"},
            # Genuinely new: fsspec keys its instance cache on the
            # storage options, so without this every call would hand
            # back the same object and "fresh" would mean nothing.
            skip_instance_cache=True,
        )

    return factory


@pytest.fixture(scope="session")
def pelicanfs_fs(new_pelicanfs):
    """The pure-Python implementation, for differential comparison."""
    return new_pelicanfs()


# --------------------------------------------------------------------- #
# The tripwire                                                          #
# --------------------------------------------------------------------- #


@pytest.fixture(scope="session", autouse=True)
def _containment_tripwire(tmp_path_factory: pytest.TempPathFactory):
    """Fail loudly if anything is written outside the session root.

    The fuzzers generate hostile object *names*, and the way a hostile
    name does damage is by becoming a local path: ``os.path.join(dest,
    "/etc/passwd")`` is ``"/etc/passwd"``.  ``fuzz_export`` is built so
    that cannot happen -- local names are opaque hashes, and the one
    place a real name reaches the filesystem is containment-checked --
    but a control you cannot observe failing is a control you do not
    have.

    So: a canary just *outside* the session root, plus a snapshot of
    that directory, both checked at teardown.  It is cheap, it runs
    once, and the day it fires it says the containment argument above
    is wrong.
    """
    outside = tmp_path_factory.getbasetemp()
    canary = outside / "containment-canary.txt"
    payload = b"If this file changes, the harness escaped its session root.\n"
    canary.write_bytes(payload)
    before = {p.name: p.is_dir() for p in outside.iterdir()}
    try:
        yield
    finally:
        violations = tripwire_violations(outside, canary, payload, before)
        assert not violations, "\n".join(violations)
