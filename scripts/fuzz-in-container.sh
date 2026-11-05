#!/usr/bin/env bash
#
# Run the test suite inside the container defined by docker/Dockerfile,
# with this working tree mounted READ-ONLY.
#
# Use this for any run of the generative suite.  The fuzzer builds
# hostile object names deliberately, and the harness that is supposed
# to keep them away from local paths is itself under development; a
# mistake there would otherwise write to the developer's home
# directory.  Read-only is the whole point -- the container copies the
# tree to scratch before touching anything.
#
# Usage:
#   scripts/fuzz-in-container.sh [pytest args...]
#
#   scripts/fuzz-in-container.sh -q
#   scripts/fuzz-in-container.sh test/test_fuzz_paths.py -x
#   HYPOTHESIS_PROFILE=soak scripts/fuzz-in-container.sh -q -k fuzz
#
# Environment:
#   IMAGE             image tag to use/build (default pelicanfs-native-fuzz)
#   REBUILD           non-empty to force a rebuild
#   HYPOTHESIS_PROFILE forwarded into the container
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-pelicanfs-native-fuzz}"

if [[ -n "${REBUILD:-}" ]] || ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "building ${IMAGE} (first run takes a few minutes)" >&2
    docker build -t "${IMAGE}" -f "${REPO_ROOT}/docker/Dockerfile" "${REPO_ROOT}"
fi

# --read-only would also freeze /tmp and the scratch copy, so the mount
# alone carries the guarantee that matters: the host tree cannot be
# written.  Nothing else of the host is mounted.
exec docker run --rm -i \
    -v "${REPO_ROOT}:/src:ro" \
    -e "HYPOTHESIS_PROFILE=${HYPOTHESIS_PROFILE:-}" \
    "${IMAGE}" "$@"
