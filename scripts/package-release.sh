#!/usr/bin/env bash
# package-release.sh — Creates a distributable tarball for a tagged release.
# Usage: bash scripts/package-release.sh <version-tag>
#   e.g. bash scripts/package-release.sh v2.0.0
set -euo pipefail

VERSION="${1:?Usage: package-release.sh <version-tag>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
RELEASE_NAME="redboss-discovery-kit-${VERSION}"
STAGING="${DIST_DIR}/${RELEASE_NAME}"

echo "📦 Packaging ${RELEASE_NAME} ..."

rm -rf "${DIST_DIR}"
mkdir -p "${STAGING}"

# Include only the files needed to run the tool
cp "${REPO_ROOT}/dk"                       "${STAGING}/"
cp "${REPO_ROOT}/schemas.py"               "${STAGING}/"
cp "${REPO_ROOT}/requirements.txt"         "${STAGING}/"
cp "${REPO_ROOT}/dk-manifest.yml"          "${STAGING}/"
cp "${REPO_ROOT}/dk-manifest-reference.yml" "${STAGING}/"
cp "${REPO_ROOT}/README.md"                "${STAGING}/"
cp "${REPO_ROOT}/LICENSE"                  "${STAGING}/"
cp "${REPO_ROOT}/ACKNOWLEDGEMENTS.md"      "${STAGING}/"

# Copy optional documentation if present
[ -f "${REPO_ROOT}/CHANGELOG.md" ]    && cp "${REPO_ROOT}/CHANGELOG.md"    "${STAGING}/"
[ -f "${REPO_ROOT}/CONTRIBUTING.md" ] && cp "${REPO_ROOT}/CONTRIBUTING.md" "${STAGING}/"
[ -f "${REPO_ROOT}/TUTORIAL.md" ]     && cp "${REPO_ROOT}/TUTORIAL.md"     "${STAGING}/"

# Create the tarball
TARBALL="${DIST_DIR}/${RELEASE_NAME}.tar.gz"
tar -czf "${TARBALL}" -C "${DIST_DIR}" "${RELEASE_NAME}"

# Generate SHA-256 checksum
CHECKSUM="${TARBALL}.sha256"
(cd "${DIST_DIR}" && sha256sum "${RELEASE_NAME}.tar.gz" > "${RELEASE_NAME}.tar.gz.sha256")

echo "✅ Tarball:   ${TARBALL}"
echo "✅ Checksum:  ${CHECKSUM}"
echo "📁 Contents:"
tar -tzf "${TARBALL}"
