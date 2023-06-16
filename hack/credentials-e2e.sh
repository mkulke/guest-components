#!/bin/bash

set -euo pipefail

CRED_RESOURCE=default/credential/coco
REGISTRY_USER=ci-user
REGISTRY_PASSWORD=ci-password

cleanup() {
  if [ -z "${BUILD_DIR:-}" ]; then
	rm -rf "$build_dir"
  fi
  docker ps -q --filter "name=registry" | grep -q . && docker rm -f registry
  jobs -p | grep -q . && jobs -p | xargs kill
}
trap 'cleanup' EXIT

bold_echo() {
  echo -e "\033[1m${1}\033[0m"
}

# shellcheck source=hack/common/registry.sh
. "$(dirname "${BASH_SOURCE[0]}")/common/registry.sh"
# shellcheck source=hack/common/kbs.sh
. "$(dirname "${BASH_SOURCE[0]}")/common/kbs.sh"
# shellcheck source=hack/common/attestation-agent.sh
. "$(dirname "${BASH_SOURCE[0]}")/common/attestation-agent.sh"

build_dir="${BUILD_DIR:-$(mktemp -d)}"
pushd "$build_dir"
mkdir -p bin

[ -d "./image-rs" ] || git clone https://github.com/confidential-containers/image-rs.git
[ -d "./attestation-agent" ] || git clone https://github.com/confidential-containers/attestation-agent.git
[ -d "./kbs" ] || git clone https://github.com/confidential-containers/kbs.git

start_kbs
start_aa

start_tls_registry_with_auth

bold_echo "Store credentials in kbs..."
cat <<EOF > auth.json
{
	"auths": {
		"localhost:5000": {
			"auth": "$(echo -n "$REGISTRY_USER:$REGISTRY_PASSWORD" | base64)"
		}
	}
}
EOF
mkdir -p "/opt/confidential-containers/kbs/repository/$(dirname "$CRED_RESOURCE")"
cp auth.json "/opt/confidential-containers/kbs/repository/${CRED_RESOURCE}"

bold_echo "Store image in local registry..."
docker login -u "$REGISTRY_USER" -p "$REGISTRY_PASSWORD" localhost:5000
skopeo copy docker://busybox docker://localhost:5000/coco/busybox:v1

bold_echo "Run registry credentials test..."
pushd image-rs
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test \
	--features getresource,snapshot-overlayfs,oci-distribution/rustls-tls-native-roots \
	-- --include-ignored --test retrieve_credentials_via_kbs --nocapture
