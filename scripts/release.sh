#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
release_version="${1:-0.1.0-dev}"
if [[ ! "$release_version" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo 'Version must contain only letters, digits, dots, underscores or hyphens.' >&2
  exit 2
fi
export CGO_ENABLED=0
# Collect the modules actually used by every target, including platform-only
# imports. Check failures here instead of hiding them in process substitution.
release_modules=""
for release_os in darwin linux; do
  for release_arch in arm64 amd64; do
    release_target_modules="$(GOOS="$release_os" GOARCH="$release_arch" go list -deps \
      -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}' ./cmd/utlsproxy)"
    release_modules+=$'\n'"$release_target_modules"
  done
done
mkdir -p dist/THIRD_PARTY_LICENSES
release_go_license="${GO_LICENSE:-$(go env GOROOT)/LICENSE}"
if [[ ! -f "$release_go_license" && -z "${GO_LICENSE:-}" && -f /usr/share/licenses/go/LICENSE ]]; then
  # Arch packages the toolchain license separately from GOROOT.
  release_go_license=/usr/share/licenses/go/LICENSE
fi
if [[ ! -f "$release_go_license" ]]; then
  echo 'Go license not found; set GO_LICENSE to the toolchain license file.' >&2
  exit 1
fi
cp -f "$release_go_license" dist/THIRD_PARTY_LICENSES/Go.LICENSE
while IFS=' ' read -r release_module release_module_dir; do
  [[ -n "$release_module_dir" ]] || continue
  for release_notice in LICENSE LICENSE.txt LICENSE.md NOTICE COPYING \
      dicttls/LICENSE zstd/internal/xxhash/LICENSE.txt; do
    if [[ -f "${release_module_dir}/${release_notice}" ]]; then
      cp -f "${release_module_dir}/${release_notice}" \
        "dist/THIRD_PARTY_LICENSES/${release_module//\//_}.${release_notice//\//_}"
    fi
  done
done <<<"$(sort -u <<<"$release_modules")"
release_archives=()
for release_os in darwin linux; do
  for release_arch in arm64 amd64; do
    release_name="utlsproxy-${release_version}-${release_os}-${release_arch}"
    release_dir="dist/${release_name}"
    mkdir -p "$release_dir"
    echo "Building ${release_os}/${release_arch}"
    GOOS="$release_os" GOARCH="$release_arch" go build -trimpath \
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
