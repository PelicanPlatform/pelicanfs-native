# A disposable Linux environment for running the fuzzer.
#
# The point is not reproducibility -- CI already covers that -- but
# containment.  The generative suite builds hostile object names on
# purpose: names holding "..", a leading "/", NUL bytes, names longer
# than any path component may be.  The harness is written so that none
# of them can reach a local path, but the harness is also the thing
# under development, and a traversal bug in it would write to whatever
# the test process can write to.  On a laptop that is a home directory
# full of other checkouts.
#
# So the run script mounts the working tree READ-ONLY and copies it to
# a scratch path inside the container.  A total failure of the harness
# then costs a container, and the host cannot be touched at all.
#
# Everything the suite needs is baked in, so a run needs no network and
# no Go toolchain:
#   * libpelicanclient, built from pelican-c and installed to a scratch
#     prefix, exactly as CI builds it;
#   * the pinned pelican/pelican-server release binaries;
#   * a virtualenv with the third-party dependencies already resolved,
#     so a run only has to compile the CFFI extension.
FROM golang:1.26-bookworm

ARG PELICAN_C_REF=main
ARG PELICAN_VERSION=v26.0.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl git pkg-config python3-dev python3-venv rsync \
 && rm -rf /var/lib/apt/lists/*

# Built from source rather than downloaded: pelican-c has no released
# tarball yet, and CI pins the same ref so an ABI change breaks both.
RUN git clone --depth 1 --branch "${PELICAN_C_REF}" \
        https://github.com/PelicanPlatform/pelican-c /src/pelican-c \
 && make -C /src/pelican-c install PREFIX=/opt/pelican-c \
 && rm -rf /src/pelican-c /root/.cache/go-build
ENV PELICAN_C_PREFIX=/opt/pelican-c

COPY scripts/fetch-pelican.sh /usr/local/bin/fetch-pelican.sh
RUN PELICAN_VERSION="${PELICAN_VERSION}" bash /usr/local/bin/fetch-pelican.sh /opt/pelican-bin
ENV PELICANFS_NATIVE_SERVER_BINARY=/opt/pelican-bin/pelican-server \
    PELICANFS_NATIVE_CLIENT_BINARY=/opt/pelican-bin/pelican

# The third-party dependencies are installed here only to warm the
# layer; a run still does the real resolution with `pip install -e .
# --group differential`, which is then close to a no-op.  Listing them
# twice is a known cost -- pyproject stays authoritative, and a drift
# here costs a slower run, not a wrong one.  The aiowebdav2 cap is the
# one that matters: without it pelicanfs installs against an
# incompatible 1.x and its ls()/info() raise AttributeError.
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --upgrade --quiet pip
ENV PATH=/opt/venv/bin:$PATH
RUN pip install --quiet \
        "cffi>=1.17" "fsspec>=2024.3.1" \
        "pytest>=8" "pytest-timeout" \
        "pelicanfs>=1.3" "hypothesis>=6.100" "aiowebdav2<1"

COPY docker/run-suite.sh /usr/local/bin/run-suite
RUN chmod +x /usr/local/bin/run-suite

# Not root, for two reasons.  The ordinary one is that nothing here
# needs it.  The specific one is that pelican-server drops privileges
# to the `xrootd` user when it finds itself running as root, and exits
# if that user does not exist -- which it does not here, because this
# federation is deliberately XRootD-free (a posixv2 origin and a V2
# cache).  CI never meets this because GitHub runners are not root.
# The venv and the scratch copy both have to be writable: an editable
# install writes into site-packages.
RUN useradd --create-home --shell /bin/bash fuzz \
 && mkdir -p /build \
 && chown -R fuzz:fuzz /opt/venv /build
USER fuzz

ENTRYPOINT ["/usr/local/bin/run-suite"]
