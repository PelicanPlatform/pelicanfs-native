#!/usr/bin/env bash
#
# Copy the read-only working tree to a scratch path, build the CFFI
# extension against the Linux libpelicanclient in the image, and run
# whatever pytest arguments were given.
#
# The copy is what keeps the host safe: /src is mounted read-only, so
# nothing the suite does -- including a traversal bug in the harness
# itself -- can reach the working tree, let alone anything outside it.
set -euo pipefail

# Excluded because they are host build products: a macOS virtualenv and
# a Darwin CFFI extension are not merely useless here, they would be
# picked up in preference to the Linux ones.
rsync -a --quiet \
    --exclude '.venv/' \
    --exclude '.git/' \
    --exclude 'build/' \
    --exclude '*.egg-info/' \
    --exclude '__pycache__/' \
    --exclude '*.so' \
    --exclude '*.dylib' \
    --exclude 'src/pelicanfs_native/_pelican_cffi.*' \
    /src/ /build/

cd /build
# The full group, not --no-deps: the image only warms the dependency
# set, and pyproject stays the authority on what it is.
pip install --quiet -e . --group differential

exec pytest "$@"
