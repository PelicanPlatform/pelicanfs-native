#!/usr/bin/env bash
#
# Download the `pelican` and `pelican-server` binaries from a GitHub
# release and print the directory holding them.  The test harness runs
# a real federation, so CI needs the server binary; building it from
# source would mean a Go toolchain and several minutes per job.
#
# Usage:
#   scripts/fetch-pelican.sh [destination]
#
# Environment:
#   PELICAN_VERSION  release tag to fetch (default: the latest release).
#                    Pin this in CI -- "latest" makes a green run
#                    unreproducible.
#   GITHUB_TOKEN     optional; raises the API rate limit.

set -euo pipefail

DEST="${1:-${PWD}/.pelican-bin}"
REPO="PelicanPlatform/pelican"

case "$(uname -s)" in
    Linux)  OS="Linux" ;;
    Darwin) OS="Darwin" ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

auth=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

version="${PELICAN_VERSION:-}"
if [[ -z "${version}" ]]; then
    version=$(curl -fsSL "${auth[@]}" "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
    if [[ -z "${version}" ]]; then
        echo "could not resolve the latest ${REPO} release; set PELICAN_VERSION" >&2
        exit 1
    fi
    echo "resolved latest release: ${version}" >&2
fi

# GoReleaser strips the leading "v" from the version inside the archive's
# wrapper directory but keeps it in the tag.
bare="${version#v}"

mkdir -p "${DEST}"
workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT

fetch_one() {
    local archive_name="$1" wrapper="$2" binary="$3"
    local url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"
    echo "fetching ${url}" >&2
    curl -fsSL "${auth[@]}" -o "${workdir}/${archive_name}" "${url}"
    # Extract into its own empty directory: a release archive is
    # untrusted input and should not be unpacked over anything.
    local out="${workdir}/${wrapper}-extract"
    mkdir -p "${out}"
    tar -xzf "${workdir}/${archive_name}" -C "${out}"
    local found
    found=$(find "${out}" -type f -name "${binary}" -perm -u+x | head -n1)
    if [[ -z "${found}" ]]; then
        echo "archive ${archive_name} contained no ${binary} binary" >&2
        exit 1
    fi
    install -m 0755 "${found}" "${DEST}/${binary}"
}

fetch_one "pelican_${OS}_${ARCH}.tar.gz" "pelican-${bare}" "pelican"
fetch_one "pelican-server_${OS}_${ARCH}.tar.gz" "pelican-server-${bare}" "pelican-server"

"${DEST}/pelican" --version >&2 || true
echo "${DEST}"
