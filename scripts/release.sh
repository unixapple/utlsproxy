#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
release_version="${1:-0.1.0-dev}"
if [[ ! "$release_version" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo 'Version must contain only letters, digits, dots, underscores or hyphens.' >&2
  exit 2
fi
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.1}"
# Populate source directories before collecting notices on a fresh checkout.
go list -deps ./cmd/utlsproxy >/dev/null
mkdir -p dist/THIRD_PARTY_LICENSES
cp -f "$(go env GOROOT)/LICENSE" dist/THIRD_PARTY_LICENSES/Go.LICENSE
while IFS=' ' read -r release_module release_module_dir; do
  [[ -n "$release_module_dir" ]] || continue
  for release_notice in LICENSE LICENSE.txt LICENSE.md NOTICE COPYING \
      dicttls/LICENSE zstd/internal/xxhash/LICENSE.txt; do
    if [[ -f "${release_module_dir}/${release_notice}" ]]; then
      cp -f "${release_module_dir}/${release_notice}" \
        "dist/THIRD_PARTY_LICENSES/${release_module//\//_}.${release_notice//\//_}"
    fi
  done
done < <(go list -m -f '{{if not .Main}}{{.Path}} {{.Dir}}{{end}}' all)
release_archives=()
for release_os in darwin linux; do
  for release_arch in arm64 amd64; do
    release_name="utlsproxy-${release_version}-${release_os}-${release_arch}"
    release_dir="dist/${release_name}"
    mkdir -p "$release_dir"
    echo "Building ${release_os}/${release_arch}"
    CGO_ENABLED=0 GOOS="$release_os" GOARCH="$release_arch" go build -trimpath \
      -ldflags "-s -w -X main.version=${release_version}" \
      -o "${release_dir}/utlsproxy" ./cmd/utlsproxy
    cp README.md SPEC.md DELIVERY.md LICENSE go.mod go.sum "$release_dir/"
    cp -Rf docs examples dist/THIRD_PARTY_LICENSES "$release_dir/"
    tar -czf "dist/${release_name}.tar.gz" -C "$release_dir" \
      utlsproxy README.md SPEC.md DELIVERY.md LICENSE go.mod go.sum docs examples THIRD_PARTY_LICENSES
    release_archives+=("${release_name}.tar.gz")
  done
done
cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${release_archives[@]}" > SHA256SUMS
else
  shasum -a 256 "${release_archives[@]}" > SHA256SUMS
fi
echo 'Created four archives and dist/SHA256SUMS.'
